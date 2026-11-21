//! The devices, the links and the hosts of the demo estate in one cycle:
//! a Frankfurt site and a Paris site, each with an NX-OS data centre
//! fabric, an IOS-XE campus, 2 IOS-XR WAN routers and an IOS-XE internet
//! edge router.

use std::net::Ipv4Addr;

use super::model::*;

/// The short name of each site.
pub const SITES: [&str; 2] = ["fra", "par"];

/// The AS of the data centre fabric, of the WAN and of the internet edge of
/// each site, and the AS of the provider of each site.
const FABRIC_AS: [u32; 2] = [65110, 65120];
const WAN_AS: [u32; 2] = [65010, 65020];
const EDGE_AS: u32 = 64500;
const ISP_AS: [u32; 2] = [64496, 64511];

/// The VRF of the business applications, its layer 3 VNI and its VLAN.
pub const TENANT: &str = "PROD";
const L3VNI: u32 = 50001;
const L3VNI_VLAN: u16 = 3001;

/// The campus VLANs.
const MGMT_VLAN: u16 = 99;
const USERS: u16 = 110;
const PRINTERS: u16 = 120;
const TRANSIT: u16 = 900;

/// The server VLANs of each leaf pair of each site, with their names and
/// their hosts: a name and the last byte of the address.
type Pair = &'static [(u16, &'static str, &'static [(&'static str, u8)])];
const FRA_PAIRS: [Pair; 3] = [
    &[
        (
            10,
            "SHOP-WEB",
            &[("web01", 11), ("web02", 12), ("web03", 13), ("web04", 14)],
        ),
        (20, "SHOP-APP", &[("app01", 11), ("app02", 12)]),
    ],
    &[
        (30, "SHOP-DB", &[("db01", 11), ("db02", 12)]),
        (40, "INFRA", &[("dns01", 53), ("ntp01", 123), ("ad01", 10)]),
    ],
    &[(50, "ERP", &[("erp01", 11), ("erp02", 12), ("erp-db01", 21)])],
];
const PAR_PAIRS: [Pair; 2] = [
    &[
        (10, "SHOP-WEB", &[("web11", 11), ("web12", 12)]),
        (40, "INFRA", &[("dns02", 53), ("ad02", 10)]),
    ],
    &[
        (30, "SHOP-DB", &[("db11", 11)]),
        (60, "FILES", &[("files01", 11), ("files02", 12)]),
    ],
];

/// The service VLAN of the border pair of each site.
const BORDER: [Pair; 2] = [
    &[(90, "EDGE-SERVICES", &[("lb01", 11), ("proxy01", 12)])],
    &[(90, "EDGE-SERVICES", &[("lb02", 11), ("proxy02", 12)])],
];

/// The number of access switches of each site.
const ACCESS: [usize; 2] = [8, 4];

struct Builder {
    e: Estate,
    /// The next free /31 of each p2p range, by range.
    p2p: std::collections::BTreeMap<[u8; 3], u8>,
    hosts: u64,
}

fn sc(site: usize) -> u8 {
    u8::try_from(site + 1).expect("2 sites")
}

impl Builder {
    fn dev(&mut self, name: &str, os: Os, role: Role, site: usize, model: &'static str) -> usize {
        let idx = self.e.devs.len();
        let n = u64::try_from(idx + 1).expect("few devices");
        let version = match os {
            Os::Nxos => "10.3(4a)",
            Os::Iosxe => "17.09.04a",
            Os::Iosxr => "7.11.2",
        };
        let in_site = self.e.devs.iter().filter(|d| d.site == site).count();
        self.e.devs.push(Dev {
            name: name.to_string(),
            os,
            role,
            site,
            model,
            serial: format!("DEMO{:02}{:04}", site + 1, idx + 1),
            version,
            mgmt: ip(10, 255, sc(site), 10 + u8::try_from(in_site).expect("few devices")),
            ifaces: Vec::new(),
            vlans: Vec::new(),
            l3vni: None,
            bgp: None,
            vpc_domain: None,
            vpc_peer: None,
            vtep: None,
            nve_peers: Vec::new(),
            acls: Vec::new(),
            statics: Vec::new(),
            stp_priority: 32768,
            base_mac: 0x025e_0000_0000 | (n << 16),
        });
        idx
    }

    /// Adds an interface with the next MAC of the device.
    fn add(&mut self, dev: usize, mut i: Iface) -> &mut Iface {
        let d = &mut self.e.devs[dev];
        let has_mac = !matches!(
            i.mode,
            Mode::Loopback | Mode::Nve | Mode::PortChannel(_) | Mode::Unused
        );
        if has_mac && i.mac.is_none() {
            let n = u64::try_from(d.ifaces.len() + 1).expect("few interfaces");
            i.mac = Some(d.base_mac + n);
        }
        d.ifaces.push(i);
        d.ifaces.last_mut().expect("just pushed")
    }

    fn link(&mut self, a: usize, pa: &str, b: usize, pb: &str) {
        self.e.links.push(Link {
            a: (a, pa.to_string()),
            b: (b, pb.to_string()),
        });
    }

    /// The next /31 of a range `a.b.c.0/24`: the 2 addresses.
    fn p2p(&mut self, range: [u8; 3]) -> (Ipv4Addr, Ipv4Addr) {
        let n = self.p2p.entry(range).or_insert(0);
        let x = *n;
        *n += 2;
        (
            ip(range[0], range[1], range[2], x),
            ip(range[0], range[1], range[2], x + 1),
        )
    }

    /// A routed link with a /31 of `range` between 2 new ports.
    #[allow(clippy::too_many_arguments)]
    fn routed(
        &mut self,
        range: [u8; 3],
        (a, pa, va, da): (usize, &str, &str, &str),
        (b, pb, vb, db): (usize, &str, &str, &str),
        cost: (u32, Proto, Proto),
        ospf: bool,
    ) -> (Ipv4Addr, Ipv4Addr) {
        let (x, y) = self.p2p(range);
        for (dev, port, vrf, desc, addr, proto) in
            [(a, pa, va, da, x, cost.1), (b, pb, vb, db, y, cost.2)]
        {
            let i = self.add(dev, Iface::new(port, desc, Mode::Routed));
            i.vrf = vrf.to_string();
            i.addr = Some((addr, 31));
            i.routing = Some((cost.0, proto));
            i.ospf = ospf;
        }
        self.link(a, pa, b, pb);
        (x, y)
    }

    fn host(&mut self, name: &str, ip: Ipv4Addr, plen: u8, gateway: Ipv4Addr, dev: usize, port: &str, vlan: u16) {
        self.hosts += 1;
        self.e.hosts.push(Host {
            name: name.to_string(),
            mac: 0x025e_0000_0000 | u64::from(u32::from(ip)),
            ip,
            plen,
            gateway,
            dev,
            port: port.to_string(),
            vlan,
        });
    }

    fn loopback(&mut self, dev: usize, name: &str, addr: Ipv4Addr, ospf: bool) -> &mut Iface {
        let i = self.add(dev, Iface::new(name, "", Mode::Loopback));
        i.addr = Some((addr, 32));
        i.ospf = ospf;
        i
    }

    fn mgmt(&mut self, dev: usize, name: &str, vrf: &str) {
        let addr = self.e.devs[dev].mgmt;
        let site = self.e.devs[dev].site;
        let i = self.add(dev, Iface::new(name, "oob management", Mode::Mgmt));
        i.vrf = vrf.to_string();
        i.addr = Some((addr, 24));
        i.speed = 1000;
        self.e.devs[dev].statics.push(Static {
            vrf: vrf.to_string(),
            prefix: (ip(0, 0, 0, 0), 0),
            next_hop: ip(10, 255, sc(site), 1),
        });
    }

    fn neighbor(&mut self, dev: usize, n: Neighbor) {
        self.e.devs[dev]
            .bgp
            .as_mut()
            .expect("the device has BGP")
            .neighbors
            .push(n);
    }
}

fn nbr(vrf: &str, addr: Ipv4Addr, remote_as: u32, desc: &str) -> Neighbor {
    Neighbor {
        vrf: vrf.to_string(),
        addr,
        remote_as,
        desc: desc.to_string(),
        update_source: None,
        evpn: false,
        rr_client: false,
        up: true,
    }
}

/// The access list on the hand-off of each border leaf of a site toward
/// the WAN.
fn dc_in(site: usize, cycle: usize) -> Acl {
    let s = sc(site);
    let mut entries = vec![
        (
            10,
            format!("deny tcp any 10.{s}1.30.0/24 eq 1433"),
        ),
        (20, format!("deny tcp any 10.{s}1.30.0/24 eq 5432")),
        (100, "permit ip any any".to_string()),
    ];
    if site == 0 && cycle >= 2 {
        entries.insert(2, (30, format!("deny tcp any 10.{s}1.10.0/24 eq 22")));
    }
    Acl {
        name: "DC-IN".into(),
        entries,
    }
}

/// The estate of a cycle, from 1.
pub fn estate(cycle: usize) -> Estate {
    let mut b = Builder {
        e: Estate::default(),
        p2p: Default::default(),
        hosts: 0,
    };
    let mut wans = [[0usize; 2]; 2];
    let mut borders = [[0usize; 2]; 2];
    let mut inets = [0usize; 2];
    let mut cores = [[0usize; 2]; 2];
    for site in 0..2 {
        let s = sc(site);
        let n = SITES[site];
        // The WAN routers.
        for k in 0..2 {
            let w = b.dev(&format!("{n}-wan{}", k + 1), Os::Iosxr, Role::Wan, site, "ASR-9901");
            wans[site][k] = w;
            b.loopback(w, "Loopback0", ip(10, s * 10 + 7, 0, u8::try_from(k + 1).expect("2")), true);
            b.e.devs[w].bgp = Some(Bgp {
                asn: WAN_AS[site],
                router_id: ip(10, s * 10 + 7, 0, u8::try_from(k + 1).expect("2")),
                neighbors: Vec::new(),
            });
            b.mgmt(w, "MgmtEth0/RP0/CPU0/0", "MGMT");
        }
        let (w1, w2) = (wans[site][0], wans[site][1]);
        b.routed(
            [10, s * 10 + 7, 1],
            (w1, "TenGigE0/0/0/1", "default", &format!("{n}-wan2"), ),
            (w2, "TenGigE0/0/0/1", "default", &format!("{n}-wan1")),
            (10, Proto::Ospf, Proto::Ospf),
            true,
        );
        for (a, z) in [(0usize, 1usize), (1, 0)] {
            let (me, other) = (wans[site][a], wans[site][z]);
            let mut x = nbr(
                "default",
                ip(10, s * 10 + 7, 0, u8::try_from(z + 1).expect("2")),
                WAN_AS[site],
                &format!("{n}-wan{}", z + 1),
            );
            x.update_source = Some("Loopback0".into());
            let _ = other;
            b.neighbor(me, x);
        }

        // The data centre fabric.
        let pairs: &[Pair] = if site == 0 { &FRA_PAIRS } else { &PAR_PAIRS };
        let mut spines = [0usize; 2];
        for k in 0..2 {
            let sp = b.dev(
                &format!("{n}-dc-spine{}", k + 1),
                Os::Nxos,
                Role::Spine,
                site,
                "N9K-C9332C",
            );
            spines[k] = sp;
            let id = ip(10, s * 10, 0, u8::try_from(k + 1).expect("2"));
            b.loopback(sp, "loopback0", id, true);
            b.e.devs[sp].bgp = Some(Bgp {
                asn: FABRIC_AS[site],
                router_id: id,
                neighbors: Vec::new(),
            });
            b.mgmt(sp, "mgmt0", "management");
        }
        // The leaves: the server pairs, then the border pair.
        let mut leaves: Vec<(usize, usize, Option<usize>)> = Vec::new();
        for p in 0..=pairs.len() {
            for m in 0..2 {
                let border = p == pairs.len();
                let name = if border {
                    format!("{n}-dc-bl{}", m + 1)
                } else {
                    format!("{n}-dc-leaf{}", 2 * p + m + 1)
                };
                let role = if border { Role::Border } else { Role::Leaf };
                let l = b.dev(&name, Os::Nxos, role, site, "N9K-C93180YC-FX");
                leaves.push((l, m, (!border).then_some(p)));
            }
        }
        let mut port_of_spine = 0;
        for (li, &(l, m, pair)) in leaves.iter().enumerate() {
            let border = pair.is_none();
            let pair_no = pair.map_or(9, |p| p + 1);
            let num = if border { 21 + m } else { 11 + li };
            let num = u8::try_from(num).expect("few leaves");
            let id = ip(10, s * 10, 0, num);
            b.loopback(l, "loopback0", id, true);
            let lo1 = b.loopback(l, "loopback1", ip(10, s * 10, 1, num), true);
            let shared = ip(10, s * 10, 2, u8::try_from(pair_no).expect("few pairs"));
            lo1.secondary = Some((shared, 32));
            {
                let d = &mut b.e.devs[l];
                d.vtep = Some(shared);
                d.vpc_domain = Some(u32::from(s) * 100 + u32::try_from(pair_no).expect("few"));
                d.vpc_peer = Some(if m == 0 { l + 1 } else { l - 1 });
                d.l3vni = Some((TENANT.into(), L3VNI, L3VNI_VLAN));
                d.bgp = Some(Bgp {
                    asn: FABRIC_AS[site],
                    router_id: id,
                    neighbors: Vec::new(),
                });
                d.vlans.push(Vlan {
                    id: L3VNI_VLAN,
                    name: "PROD-L3VNI".into(),
                    vni: Some(L3VNI),
                });
            }
            // The uplinks to the spines.
            port_of_spine += 1;
            for (k, &sp) in spines.iter().enumerate() {
                let up = format!("Ethernet1/{}", 49 + k);
                let down = format!("Ethernet1/{port_of_spine}");
                let lname = b.e.devs[l].name.clone();
                let sname = b.e.devs[sp].name.clone();
                b.routed(
                    [10, s * 10, 100],
                    (sp, &down, "default", &lname),
                    (l, &up, "default", &sname),
                    (10, Proto::Ospf, Proto::Ospf),
                    true,
                );
                let mut x = nbr("default", id, FABRIC_AS[site], &lname);
                x.update_source = Some("loopback0".into());
                x.evpn = true;
                x.rr_client = true;
                b.neighbor(sp, x);
                let mut y = nbr(
                    "default",
                    ip(10, s * 10, 0, u8::try_from(k + 1).expect("2")),
                    FABRIC_AS[site],
                    &sname,
                );
                y.update_source = Some("loopback0".into());
                y.evpn = true;
                b.neighbor(l, y);
            }
            // The VLANs and the SVIs of the pair.
            let vlans: Vec<(u16, &str, &[(&str, u8)])> = match pair {
                Some(p) => pairs[p].to_vec(),
                None => BORDER[site].to_vec(),
            };
            for &(v, name, _) in &vlans {
                b.e.devs[l].vlans.push(Vlan {
                    id: v,
                    name: name.to_string(),
                    vni: Some(10000 + u32::from(v)),
                });
                let i = b.add(l, Iface::new(&format!("Vlan{v}"), name, Mode::Svi(v)));
                i.vrf = TENANT.into();
                i.addr = Some((ip(10, s * 10 + 1, u8::try_from(v).expect("small"), 1), 24));
                i.anycast = true;
            }
            let i = b.add(
                l,
                Iface::new(&format!("Vlan{L3VNI_VLAN}"), "PROD-L3VNI", Mode::Svi(L3VNI_VLAN)),
            );
            i.vrf = TENANT.into();
            i.ip_forward = true;
            // The peer link.
            let trunk: Vec<u16> = vlans.iter().map(|v| v.0).chain([L3VNI_VLAN]).collect();
            for port in ["Ethernet1/53", "Ethernet1/54"] {
                b.add(l, Iface::new(port, "vpc peer-link", Mode::Member(1, trunk.clone())));
            }
            let mac = b.e.devs[l].iface("Ethernet1/53").mac;
            let po = b.add(l, Iface::new("port-channel1", "vpc peer-link", Mode::PortChannel(trunk)));
            po.peer_link = true;
            po.mac = mac;
            if m == 1 {
                for port in ["Ethernet1/53", "Ethernet1/54"] {
                    b.link(l - 1, port, l, port);
                }
            }
            b.add(l, Iface::new("nve1", "", Mode::Nve));
            b.mgmt(l, "mgmt0", "management");
            // The servers on orphan ports, alternating between the 2
            // switches of the pair.
            let mut port = [if border { 10 } else { 0 }; 2];
            for &(v, _, hosts) in &vlans {
                for (h, &(hname, last)) in hosts.iter().enumerate() {
                    if h % 2 != m {
                        continue;
                    }
                    port[m] += 1;
                    let pname = format!("Ethernet1/{}", port[m]);
                    b.add(l, Iface::new(&pname, &format!("{n}-{hname}"), Mode::Access(v)))
                        .speed = 25_000;
                    b.host(
                        &format!("{n}-{hname}"),
                        ip(10, s * 10 + 1, u8::try_from(v).expect("small"), last),
                        24,
                        ip(10, s * 10 + 1, u8::try_from(v).expect("small"), 1),
                        l,
                        &pname,
                        v,
                    );
                }
            }
            if border {
                borders[site][m] = l;
            }
        }
        // The tunnel ends that each leaf knows: the other pairs.
        let veps: Vec<(usize, Ipv4Addr)> = leaves
            .iter()
            .map(|&(l, _, _)| (l, b.e.devs[l].vtep.expect("a tunnel end")))
            .collect();
        for &(l, _, _) in &leaves {
            let mine = b.e.devs[l].vtep;
            let mut peers: Vec<Ipv4Addr> = veps
                .iter()
                .filter(|(_, v)| Some(*v) != mine)
                .map(|(_, v)| *v)
                .collect();
            peers.sort();
            peers.dedup();
            b.e.devs[l].nve_peers = peers;
        }
        // The border hand-off to the WAN routers.
        for k in 0..2 {
            let bl = borders[site][k];
            let w = wans[site][k];
            let (wa, ba) = b.routed(
                [10, s * 10 + 9, 0],
                (w, "TenGigE0/0/0/3", "default", &b.e.devs[bl].name.clone()),
                (bl, "Ethernet1/1", TENANT, &b.e.devs[w].name.clone()),
                (30, Proto::Ebgp, Proto::Ebgp),
                false,
            );
            let acl = dc_in(site, cycle);
            let i = b.e.devs[bl]
                .ifaces
                .iter_mut()
                .find(|i| i.name == "Ethernet1/1")
                .expect("just added");
            i.acl_in = Some(acl.name.clone());
            b.e.devs[bl].acls.push(acl);
            let bn = b.e.devs[bl].name.clone();
            let wn = b.e.devs[w].name.clone();
            b.neighbor(w, nbr("default", ba, FABRIC_AS[site], &bn));
            b.neighbor(bl, nbr(TENANT, wa, WAN_AS[site], &wn));
        }

        // The campus: the core pair and the access switches.
        for k in 0..2 {
            let c = b.dev(&format!("{n}-core{}", k + 1), Os::Iosxe, Role::Core, site, "C9500-48Y4C");
            cores[site][k] = c;
            b.e.devs[c].stp_priority = if k == 0 { 4096 } else { 8192 };
            b.loopback(c, "Loopback0", ip(10, s * 10 + 8, 255, u8::try_from(k + 1).expect("2")), true);
            for (v, name) in [
                (MGMT_VLAN, "MGMT"),
                (USERS, "USERS"),
                (PRINTERS, "PRINTERS"),
                (TRANSIT, "CORE-TRANSIT"),
            ] {
                b.e.devs[c].vlans.push(Vlan {
                    id: v,
                    name: name.into(),
                    vni: None,
                });
            }
            let w = wans[site][k];
            let wn = b.e.devs[w].name.clone();
            let cn = b.e.devs[c].name.clone();
            b.routed(
                [10, s * 10 + 8, 0],
                (w, "TenGigE0/0/0/2", "default", &cn),
                (c, "TenGigabitEthernet1/0/1", "default", &wn),
                (10, Proto::Ospf, Proto::Ospf),
                true,
            );
        }
        let (c1, c2) = (cores[site][0], cores[site][1]);
        let core_trunk = vec![MGMT_VLAN, USERS, PRINTERS, TRANSIT];
        for c in [c1, c2] {
            let other = if c == c1 { c2 } else { c1 };
            let on = b.e.devs[other].name.clone();
            for port in ["TenGigabitEthernet1/0/47", "TenGigabitEthernet1/0/48"] {
                b.add(c, Iface::new(port, &on, Mode::Member(1, core_trunk.clone())));
            }
            let mac = b.e.devs[c].iface("TenGigabitEthernet1/0/47").mac;
            let po = b.add(c, Iface::new("Port-channel1", &on, Mode::PortChannel(core_trunk.clone())));
            po.mac = mac;
        }
        for port in ["TenGigabitEthernet1/0/47", "TenGigabitEthernet1/0/48"] {
            b.link(c1, port, c2, port);
        }
        // The SVIs of the cores with HSRP; core1 is active.
        for (v, net, desc) in [
            (MGMT_VLAN, ip(10, s * 10 + 2, 99, 0), "MGMT"),
            (USERS, ip(10, s * 10 + 2, 110, 0), "USERS"),
            (PRINTERS, ip(10, s * 10 + 2, 120, 0), "PRINTERS"),
        ] {
            let o = net.octets();
            for (k, &c) in [c1, c2].iter().enumerate() {
                let me = ip(o[0], o[1], o[2], 2 + u8::try_from(k).expect("2"));
                let peer = ip(o[0], o[1], o[2], 3 - u8::try_from(k).expect("2"));
                let i = b.add(c, Iface::new(&format!("Vlan{v}"), desc, Mode::Svi(v)));
                i.addr = Some((me, 24));
                i.hsrp = Some(Hsrp {
                    group: v,
                    vip: ip(o[0], o[1], o[2], 1),
                    active: k == 0,
                    priority: if k == 0 { 110 } else { 100 },
                    peer,
                });
            }
        }
        for (k, &c) in [c1, c2].iter().enumerate() {
            let i = b.add(c, Iface::new(&format!("Vlan{TRANSIT}"), "CORE-TRANSIT", Mode::Svi(TRANSIT)));
            i.addr = Some((ip(10, s * 10 + 2, 250, 1 + u8::try_from(k).expect("2")), 29));
            i.routing = Some((10, Proto::Ospf));
            i.ospf = true;
        }
        let campus_vlans = [MGMT_VLAN, USERS, PRINTERS];
        for a in 0..ACCESS[site] {
            let an = format!("{n}-acc{}", a + 1);
            let acc = b.dev(&an, Os::Iosxe, Role::Access, site, "C9300-48P");
            for (v, name) in [(MGMT_VLAN, "MGMT"), (USERS, "USERS"), (PRINTERS, "PRINTERS")] {
                b.e.devs[acc].vlans.push(Vlan {
                    id: v,
                    name: name.into(),
                    vni: None,
                });
            }
            let a8 = u8::try_from(a).expect("few");
            let mgmt = ip(10, s * 10 + 2, 99, 10 + a8);
            b.e.devs[acc].mgmt = mgmt;
            for (k, &c) in [c1, c2].iter().enumerate() {
                let up = format!("TenGigabitEthernet1/1/{}", k + 1);
                let down = format!("TenGigabitEthernet1/0/{}", 10 + a);
                let cn = b.e.devs[c].name.clone();
                let i = b.add(acc, Iface::new(&up, &cn, Mode::Trunk(campus_vlans.to_vec())));
                i.blocked = k == 1;
                b.add(c, Iface::new(&down, &an, Mode::Trunk(campus_vlans.to_vec())));
                b.link(acc, &up, c, &down);
            }
            let i = b.add(acc, Iface::new("Vlan99", "MGMT", Mode::Svi(MGMT_VLAN)));
            i.addr = Some((mgmt, 24));
            b.e.devs[acc].statics.push(Static {
                vrf: "default".into(),
                prefix: (ip(0, 0, 0, 0), 0),
                next_hop: ip(10, s * 10 + 2, 99, 1),
            });
            // 3 users and a printer.
            let users = if site == 1 && a == 1 && cycle >= 3 { 4 } else { 3 };
            for u in 0..users {
                let port = format!("GigabitEthernet1/0/{}", u + 1);
                b.add(acc, Iface::new(&port, "user", Mode::Access(USERS))).speed = 1000;
                let hip = ip(10, s * 10 + 2, 110, 20 + 4 * a8 + u8::try_from(u).expect("few"));
                b.host(
                    &format!("{an}-pc{}", u + 1),
                    hip,
                    24,
                    ip(10, s * 10 + 2, 110, 1),
                    acc,
                    &port,
                    USERS,
                );
            }
            let port = "GigabitEthernet1/0/40";
            b.add(acc, Iface::new(port, "printer", Mode::Access(PRINTERS))).speed = 1000;
            b.host(
                &format!("{an}-printer"),
                ip(10, s * 10 + 2, 120, 20 + a8),
                24,
                ip(10, s * 10 + 2, 120, 1),
                acc,
                port,
                PRINTERS,
            );
        }
        for &c in &[c1, c2] {
            b.mgmt(c, "GigabitEthernet0/0", "Mgmt-vrf");
        }

        // The internet edge.
        let inet = b.dev(&format!("{n}-inet1"), Os::Iosxe, Role::Inet, site, "ASR1001-X");
        inets[site] = inet;
        b.loopback(inet, "Loopback0", ip(10, s * 10 + 6, 255, 1), true);
        for k in 0..2 {
            let w = wans[site][k];
            let wn = b.e.devs[w].name.clone();
            let inn = b.e.devs[inet].name.clone();
            b.routed(
                [10, s * 10 + 6, 0],
                (w, "TenGigE0/0/0/4", "default", &inn),
                (inet, &format!("TenGigabitEthernet0/1/{k}"), "default", &wn),
                (10, Proto::Ospf, Proto::Ospf),
                true,
            );
        }
        let (net, isp) = if site == 0 {
            (ip(203, 0, 113, 0), ip(203, 0, 113, 1))
        } else {
            (ip(198, 51, 100, 0), ip(198, 51, 100, 1))
        };
        let i = b.add(inet, Iface::new("GigabitEthernet0/0/0", "internet uplink", Mode::Routed));
        i.addr = Some((net, 31));
        i.speed = 1000;
        b.e.devs[inet].statics.push(Static {
            vrf: "default".into(),
            prefix: (ip(0, 0, 0, 0), 0),
            next_hop: isp,
        });
        b.e.devs[inet].bgp = Some(Bgp {
            asn: EDGE_AS,
            router_id: ip(10, s * 10 + 6, 255, 1),
            neighbors: Vec::new(),
        });
        let mut x = nbr("default", isp, ISP_AS[site], &format!("isp-edge{}", site + 1));
        x.up = !(site == 0 && cycle >= 3);
        b.neighbor(inet, x);
        b.e.externals.push(External {
            dev: inet,
            port: "GigabitEthernet0/0/0".into(),
            name: format!("isp-edge{}", site + 1),
            remote_port: "TenGigE0/0/0/7".into(),
            ip: isp,
            mac: 0x025e_ff00_0000 + u64::from(s),
        });
        b.mgmt(inet, "GigabitEthernet0", "Mgmt-intf");
    }

    // The WAN between the sites and the interconnect of the fabrics.
    for k in 0..2 {
        let (f, p) = (wans[0][k], wans[1][k]);
        let (fname, pname) = (b.e.devs[f].name.clone(), b.e.devs[p].name.clone());
        let (fa, pa) = b.routed(
            [10, 250, 0],
            (f, "TenGigE0/0/0/0", "default", &pname),
            (p, "TenGigE0/0/0/0", "default", &fname),
            (100, Proto::Ebgp, Proto::Ebgp),
            false,
        );
        b.neighbor(f, nbr("default", pa, WAN_AS[1], &pname));
        b.neighbor(p, nbr("default", fa, WAN_AS[0], &fname));
        let (f, p) = (borders[0][k], borders[1][k]);
        let (fname, pname) = (b.e.devs[f].name.clone(), b.e.devs[p].name.clone());
        let (fa, pa) = b.routed(
            [10, 99, 0],
            (f, "Ethernet1/2", TENANT, &pname),
            (p, "Ethernet1/2", TENANT, &fname),
            (120, Proto::Ebgp, Proto::Ebgp),
            false,
        );
        b.neighbor(f, nbr(TENANT, pa, FABRIC_AS[1], &pname));
        b.neighbor(p, nbr(TENANT, fa, FABRIC_AS[0], &fname));
    }
    let _ = inets;
    b.e.check();
    b.e
}
