//! The replies of an IOS-XE router or Catalyst switch, each as text.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use super::model::*;
use super::nxos::system_description;
use super::route::{Kind, Route, Tables};

/// The answer to a command that the device does not have.
pub const INVALID: &str = "% Invalid input detected at '^' marker.\n";

/// The answer of a device with no CDP.
pub const NO_CDP: &str = "% CDP is not enabled\n";

/// The short name of an interface.
pub fn short(name: &str) -> String {
    for (long, s) in [
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("Port-channel", "Po"),
        ("Loopback", "Lo"),
        ("Vlan", "Vl"),
    ] {
        if let Some(r) = name.strip_prefix(long) {
            return format!("{s}{r}");
        }
    }
    name.to_string()
}

fn switch(dev: &Dev) -> bool {
    dev.model.starts_with('C')
}

fn mgmt_vrf(dev: &Dev) -> &'static str {
    if switch(dev) { "Mgmt-vrf" } else { "Mgmt-intf" }
}

fn config(dev: &Dev) -> String {
    let mut s = String::new();
    let body = config_body(dev);
    let _ = write!(
        s,
        "Building configuration...\n\nCurrent configuration : {} bytes\n!\n! Last configuration change at 07:30:00 UTC Mon Nov 2 2026 by admin\n!\n{body}",
        body.len()
    );
    s
}

fn vlan_list(v: &[u16]) -> String {
    super::nxos::vlan_list(v)
}

fn config_body(dev: &Dev) -> String {
    let mut s = String::new();
    let sw = switch(dev);
    let _ = writeln!(
        s,
        "version 17.9\nservice timestamps debug datetime msec\nservice timestamps log datetime msec\nservice password-encryption\nno platform punt-keepalive disable-kernel-core\n!\nhostname {}\n!",
        dev.name
    );
    if dev.ifaces.iter().any(|i| i.mode == Mode::Mgmt) {
        let _ = writeln!(
            s,
            "vrf definition {}\n !\n address-family ipv4\n exit-address-family\n !\n address-family ipv6\n exit-address-family\n!",
            mgmt_vrf(dev)
        );
    }
    s.push_str(
        "no logging console\nenable secret 9 $9$DEMOSALT$FAKEHASHFAKEHASH\n!\nno aaa new-model\n",
    );
    if sw {
        let _ = writeln!(s, "switch 1 provision {}", dev.model.to_ascii_lowercase());
    }
    s.push_str("!\nip routing\n!\nno ip domain lookup\nip domain name demo.example\nlogin on-success log\n");
    if sw {
        s.push_str("vtp domain DEMO\nvtp mode transparent\n!\n");
        let ids: Vec<u16> = dev.vlans.iter().map(|v| v.id).collect();
        s.push_str("spanning-tree mode rapid-pvst\nspanning-tree extend system-id\n");
        if dev.stp_priority < 32768 {
            let _ = writeln!(
                s,
                "spanning-tree vlan {} priority {}",
                vlan_list(&ids),
                dev.stp_priority
            );
        }
        s.push_str("!\nredundancy\n mode sso\n!\n");
        for v in &dev.vlans {
            let _ = writeln!(s, "vlan {}\n name {}\n!", v.id, v.name);
        }
    } else {
        s.push_str("!\nredundancy\n mode none\n!\n");
    }
    for i in &dev.ifaces {
        let _ = writeln!(s, "interface {}", i.name);
        if !i.desc.is_empty() && i.mode != Mode::Mgmt {
            let _ = writeln!(s, " description {}", i.desc);
        }
        match &i.mode {
            Mode::PortChannel(v) | Mode::Trunk(v) => {
                let _ = writeln!(
                    s,
                    " switchport trunk allowed vlan {}\n switchport mode trunk",
                    vlan_list(v)
                );
            }
            Mode::Member(n, v) => {
                let _ = writeln!(
                    s,
                    " switchport trunk allowed vlan {}\n switchport mode trunk\n channel-group {n} mode active",
                    vlan_list(v)
                );
            }
            Mode::Access(v) => {
                let _ = writeln!(
                    s,
                    " switchport access vlan {v}\n switchport mode access\n spanning-tree portfast"
                );
            }
            Mode::Mgmt => {
                let (a, l) = i.addr.expect("an address");
                let _ = writeln!(
                    s,
                    " vrf forwarding {}\n ip address {a} {}\n negotiation auto",
                    i.vrf,
                    mask(l)
                );
            }
            Mode::Routed | Mode::Loopback | Mode::Svi(_) => {
                if sw && i.mode == Mode::Routed {
                    s.push_str(" no switchport\n");
                }
                if let Some((a, l)) = i.addr {
                    let _ = writeln!(s, " ip address {a} {}", mask(l));
                }
                if let Some(h) = &i.hsrp {
                    let _ = writeln!(
                        s,
                        " standby {g} ip {}\n standby {g} priority {}\n standby {g} preempt",
                        h.vip,
                        h.priority,
                        g = h.group
                    );
                }
                if i.ospf {
                    if i.mode == Mode::Routed {
                        s.push_str(" ip ospf network point-to-point\n");
                    }
                    let _ = writeln!(s, " ip ospf 1 area 0\n ip ospf cost {}", i.ospf_cost);
                }
                if !sw && i.mode == Mode::Routed {
                    s.push_str(" negotiation auto\n");
                }
            }
            Mode::Nve => s.push_str(" shutdown\n"),
        }
        s.push_str("!\n");
    }
    if let Some(rid) = dev
        .ifaces
        .iter()
        .find(|i| i.name == "Loopback0")
        .and_then(|i| i.addr)
    {
        let _ = writeln!(s, "router ospf 1\n router-id {}", rid.0);
        if dev.role == Role::Inet {
            s.push_str(" default-information originate\n");
        }
        s.push_str(" passive-interface default\n");
        for i in dev
            .ifaces
            .iter()
            .filter(|i| i.ospf && !i.ospf_passive && i.mode != Mode::Loopback)
        {
            let _ = writeln!(s, " no passive-interface {}", i.name);
        }
        s.push_str("!\n");
    }
    if let Some(bgp) = &dev.bgp {
        let _ = writeln!(
            s,
            "router bgp {}\n bgp router-id {}\n bgp log-neighbor-changes",
            bgp.asn, bgp.router_id
        );
        for n in &bgp.neighbors {
            let _ = writeln!(
                s,
                " neighbor {a} remote-as {}\n neighbor {a} description {}",
                n.remote_as,
                n.desc,
                a = n.addr
            );
        }
        s.push_str(" !\n address-family ipv4\n");
        for n in &bgp.neighbors {
            let _ = writeln!(
                s,
                "  neighbor {a} activate\n  neighbor {a} route-map ISP-IN in\n  neighbor {a} route-map ISP-OUT out",
                a = n.addr
            );
        }
        s.push_str(" exit-address-family\n!\n");
    }
    s.push_str("ip forward-protocol nd\nno ip http server\nno ip http secure-server\n");
    for st in &dev.statics {
        let vrf = if st.vrf == "default" {
            String::new()
        } else {
            format!("vrf {} ", st.vrf)
        };
        let _ = writeln!(
            s,
            "ip route {vrf}{} {} {}",
            st.prefix.0,
            mask(st.prefix.1),
            st.next_hop
        );
    }
    s.push_str("ip ssh version 2\n!\n");
    if dev.bgp.is_some() {
        s.push_str("ip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0\n!\nroute-map ISP-IN permit 10\n match ip address prefix-list DEFAULT-ONLY\n!\nroute-map ISP-OUT deny 10\n!\n");
    }
    let _ = writeln!(
        s,
        "snmp-server community FAKECOMMUNITY RO\n!\ncontrol-plane\n service-policy input system-cpp-policy\n!\nbanner login ^C\nDemo estate. Authorized access only.\n^C\n!\nline con 0\n stopbits 1\nline vty 0 4\n password 7 FAKEVTYPASSWORD\n login\n transport input ssh\n!\nntp server vrf {} 10.255.{}.5\n!\nend",
        mgmt_vrf(dev),
        dev.site + 1
    );
    s
}

fn version(dev: &Dev) -> String {
    let (image, family) = if switch(dev) {
        ("CAT9K_IOSXE", "Catalyst L3 Switch Software")
    } else {
        ("X86_64_LINUX_IOSD-UNIVERSALK9-M", "ASR1000 Software")
    };
    format!(
        "Cisco IOS XE Software, Version {v}\nCisco IOS Software [Cupertino], {family} ({image}), Version 17.9.4a, RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2026 by Cisco Systems, Inc.\n\nROM: IOS-XE ROMMON\n{n} uptime is 5 weeks, 6 days, 3 hours, 12 minutes\nUptime for this control processor is 5 weeks, 6 days, 3 hours, 14 minutes\nSystem returned to ROM by Reload Command\nSystem image file is \"bootflash:packages.conf\"\nLast reload reason: Reload Command\n\ncisco {m} ({cpu}) processor with 1863083K/6147K bytes of memory.\nProcessor board ID {sn}\n2 Virtual Ethernet interfaces\n48 Ten Gigabit Ethernet interfaces\n\nConfiguration register is 0x102\n",
        v = dev.version,
        n = dev.name,
        m = dev.model,
        cpu = if switch(dev) { "X86" } else { "1RU" },
        sn = dev.serial,
    )
}

fn hardware(i: &Iface, dev: &Dev) -> &'static str {
    match &i.mode {
        Mode::Svi(_) => "Ethernet SVI",
        Mode::PortChannel(_) => "EtherChannel",
        Mode::Loopback => "Loopback",
        Mode::Mgmt => "RP management port",
        _ if i.name.starts_with("TenGigabit") => "Ten Gigabit Ethernet",
        _ if switch(dev) => "Gigabit Ethernet",
        _ => "BUILT-IN-2T+6X1GE",
    }
}

fn interfaces(dev: &Dev) -> String {
    let mut s = String::new();
    for i in &dev.ifaces {
        let tail = if matches!(
            i.mode,
            Mode::Access(_) | Mode::Trunk(_) | Mode::Member(..) | Mode::PortChannel(_)
        ) {
            " (connected)"
        } else {
            ""
        };
        let _ = writeln!(s, "{} is up, line protocol is up{tail}", i.name);
        match i.mac {
            Some(m) => {
                let _ = writeln!(
                    s,
                    "  Hardware is {}, address is {} (bia {})",
                    hardware(i, dev),
                    dotted(m),
                    dotted(m)
                );
            }
            None => {
                let _ = writeln!(s, "  Hardware is {}", hardware(i, dev));
            }
        }
        if !i.desc.is_empty() {
            let _ = writeln!(s, "  Description: {}", i.desc);
        }
        if let Some((a, l)) = i.addr {
            let _ = writeln!(s, "  Internet address is {a}/{l}");
        }
        let bw = match i.mode {
            Mode::PortChannel(_) => 2 * i.speed,
            Mode::Loopback => 8_000_000 / 1000,
            _ => i.speed,
        };
        let _ = writeln!(
            s,
            "  MTU 1500 bytes, BW {} Kbit/sec, DLY 10 usec,\n     reliability 255/255, txload 1/255, rxload 1/255\n  Encapsulation ARPA, loopback not set",
            bw * 1000
        );
        if !matches!(i.mode, Mode::Loopback | Mode::Svi(_)) {
            let speed = if bw >= 1000 {
                format!("{}Gb/s", bw / 1000)
            } else {
                format!("{bw}Mb/s")
            };
            let _ = writeln!(s, "  Full-duplex, {speed}, media type is SFP");
            s.push_str("  5 minute input rate 112000 bits/sec, 41 packets/sec\n  5 minute output rate 98000 bits/sec, 37 packets/sec\n     18422011 packets input, 2210643120 bytes, 0 no buffer\n     17690455 packets output, 2005548221 bytes, 0 underruns\n");
        }
    }
    s
}

/// The LLDP block of a neighbour on a local port, in the form of IOS-XE.
pub fn lldp_entry(e: &Estate, port: &str, f: usize, fport: &str) -> String {
    let fd = &e.devs[f];
    let fi = fd.iface(fport);
    let port_id = match fd.os {
        Os::Iosxe => short(fport),
        _ => fport.to_string(),
    };
    format!(
        "------------------------------------------------\nLocal Intf: {}\nChassis id: {}\nPort id: {port_id}\nPort Description: {}\nSystem Name: {}\n\nSystem Description:\n{}\n\nTime remaining: 101 seconds\nSystem Capabilities: B,R\nEnabled Capabilities: R\nManagement Addresses:\n    IP: {}\nAuto Negotiation - not supported\nPhysical media capabilities - not advertised\nMedia Attachment Unit type - not advertised\nVlan ID: - not advertised\n\n",
        short(port),
        dotted(fd.base_mac),
        if fi.desc.is_empty() {
            "-"
        } else {
            fi.desc.as_str()
        },
        fd.name,
        system_description(fd),
        fd.mgmt
    )
}

fn lldp(e: &Estate, d: usize) -> String {
    let dev = &e.devs[d];
    let mut s = String::new();
    let mut n = 0;
    for i in &dev.ifaces {
        if let Some((f, fport)) = e.far(d, &i.name) {
            s.push_str(&lldp_entry(e, &i.name, f, &fport));
            n += 1;
        }
        for x in e
            .externals
            .iter()
            .filter(|x| x.dev == d && x.port == i.name)
        {
            let _ = write!(
                s,
                "------------------------------------------------\nLocal Intf: {}\nChassis id: {}\nPort id: {}\nPort Description: customer demo enterprise\nSystem Name: {}\n\nSystem Description:\nProvider edge router\n\nTime remaining: 98 seconds\nSystem Capabilities: R\nEnabled Capabilities: R\nManagement Addresses - not advertised\nAuto Negotiation - not supported\nPhysical media capabilities - not advertised\nMedia Attachment Unit type - not advertised\nVlan ID: - not advertised\n\n",
                short(&i.name),
                dotted(x.mac),
                x.remote_port,
                x.name
            );
            n += 1;
        }
    }
    let _ = writeln!(s, "\nTotal entries displayed: {n}");
    s
}

fn vrfs(dev: &Dev) -> String {
    let m: Vec<&Iface> = dev.ifaces.iter().filter(|i| i.mode == Mode::Mgmt).collect();
    if m.is_empty() {
        return String::new();
    }
    format!(
        "VRF {} (VRF Id = 1); default RD <not set>; default VPNID <not set>\n  New CLI format, supports multiple address-families\n  Flags: 0x1808\n  Interfaces:\n    {}\nAddress family ipv4 unicast (Table ID = 0x1):\n  Flags: 0x0\n  No Export VPN route-target communities\n  No Import VPN route-target communities\n  No import route-map\n  No global export route-map\n  No export route-map\n  VRF label distribution protocol: not configured\n  VRF label allocation mode: per-prefix\nAddress family ipv6 unicast (Table ID = 0x1E000001):\n  Flags: 0x0\n  No Export VPN route-target communities\n  No Import VPN route-target communities\n  No import route-map\n  No global export route-map\n  No export route-map\n  VRF label distribution protocol: not configured\n  VRF label allocation mode: per-prefix\n",
        mgmt_vrf(dev),
        short(&m[0].name)
    )
}

const CODES: &str = "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2, m - OMP
       n - NAT, Ni - NAT inside, No - NAT outside, Nd - NAT DIA
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       H - NHRP, G - NHRP registered, g - NHRP registration summary
       o - ODR, P - periodic downloaded static route, l - LISP
       a - application route
       + - replicated route, % - next hop override, p - overrides from PfR
       & - replicated local route overrides by connected
";

/// The classful network of an address.
fn major(a: Ipv4Addr) -> (Ipv4Addr, u8) {
    let o = a.octets()[0];
    let len = if o < 128 {
        8
    } else if o < 192 {
        16
    } else {
        24
    };
    (network(a, len), len)
}

fn table(routes: &[&Route]) -> String {
    let mut s = String::new();
    match routes.iter().find(|r| r.prefix.1 == 0) {
        Some(r) => {
            let _ = writeln!(
                s,
                "Gateway of last resort is {} to network 0.0.0.0\n",
                r.paths[0]
                    .next_hop
                    .map_or("0.0.0.0".into(), |a| a.to_string())
            );
        }
        None => s.push_str("Gateway of last resort is not set\n\n"),
    }
    let mut groups: BTreeMap<(Ipv4Addr, u8), Vec<&Route>> = BTreeMap::new();
    for r in routes {
        if r.prefix.1 == 0 {
            s.push_str(&line(r, "  "));
        } else {
            groups.entry(major(r.prefix.0)).or_default().push(r);
        }
    }
    for ((net, len), rs) in groups {
        let masks: std::collections::BTreeSet<u8> = rs.iter().map(|r| r.prefix.1).collect();
        let _ = writeln!(
            s,
            "      {net}/{len} is variably subnetted, {} subnets, {} masks",
            rs.len(),
            masks.len()
        );
        for r in rs {
            s.push_str(&line(r, "     "));
        }
    }
    s
}

/// The lines of a route, with the space between the code and the prefix.
fn line(r: &Route, pad: &str) -> String {
    let default = r.prefix.1 == 0;
    let code = match (r.kind, default) {
        (Kind::Connected, _) => "C".to_string(),
        (Kind::Local, _) => "L".to_string(),
        (Kind::Static, true) => "S*".to_string(),
        (Kind::Static, false) => "S".to_string(),
        (Kind::Ospf, true) => "O*E2".to_string(),
        (Kind::Ospf, false) => "O".to_string(),
        (Kind::Ebgp | Kind::Ibgp, true) => "B*".to_string(),
        (Kind::Ebgp | Kind::Ibgp, false) => "B".to_string(),
    };
    let head = format!("{code:<4}{pad}{}/{}", r.prefix.0, r.prefix.1);
    let indent = " ".repeat(head.len() + 1);
    let mut s = String::new();
    match r.kind {
        Kind::Connected | Kind::Local => {
            let _ = writeln!(
                s,
                "{head} is directly connected, {}",
                r.paths[0].iface.as_deref().unwrap_or("Null0")
            );
        }
        k => {
            let ad = match k {
                Kind::Static => 1,
                Kind::Ospf => 110,
                Kind::Ebgp => 20,
                _ => 200,
            };
            let metric = if k == Kind::Ospf { r.metric } else { 0 };
            for (n, p) in r.paths.iter().enumerate() {
                let nh = p.next_hop.expect("a next hop");
                let tail = match (k, &p.iface) {
                    (Kind::Ospf, Some(i)) => format!(", 5w6d, {i}"),
                    (Kind::Ebgp | Kind::Ibgp, _) => ", 5w6d".to_string(),
                    _ => String::new(),
                };
                if n == 0 {
                    let _ = writeln!(s, "{head} [{ad}/{metric}] via {nh}{tail}");
                } else {
                    let _ = writeln!(s, "{indent}[{ad}/{metric}] via {nh}{tail}");
                }
            }
        }
    }
    s
}

fn rib(dev: &Dev, routes: &[Route], all: bool) -> String {
    let mut s = String::new();
    let global: Vec<&Route> = routes.iter().filter(|r| r.vrf == "default").collect();
    let _ = write!(s, "{CODES}\n{}", table(&global));
    if all {
        let m: Vec<&Route> = routes.iter().filter(|r| r.vrf != "default").collect();
        if !m.is_empty() {
            let _ = write!(
                s,
                "\nRouting Table: {}\n{CODES}\n{}",
                mgmt_vrf(dev),
                table(&m)
            );
        }
    }
    s
}

fn arp_rows(dev: &Dev, t: &Tables, d: usize, vrf: &str) -> String {
    let mut s =
        String::from("Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n");
    for a in &t.arp[d] {
        if dev.iface(&a.iface).vrf != vrf {
            continue;
        }
        let age = if a.own {
            "-".to_string()
        } else {
            "3".to_string()
        };
        let _ = writeln!(
            s,
            "Internet  {:<15} {:>8}   {}  ARPA   {}",
            a.ip.to_string(),
            age,
            dotted(a.mac),
            a.iface
        );
    }
    s
}

fn inventory(dev: &Dev) -> String {
    let descr = if switch(dev) {
        format!("Cisco Catalyst {} Series Chassis", &dev.model[1..5])
    } else {
        "Cisco ASR1001-X Chassis".to_string()
    };
    format!(
        "NAME: \"Chassis\", DESCR: \"{descr}\"\nPID: {:<17} , VID: V02  , SN: {}\n\nNAME: \"Power Supply Module 0\", DESCR: \"Cisco 650W AC Power Supply\"\nPID: PWR-C1-650WAC     , VID: V01  , SN: DEMOPS{}\n\n",
        dev.model,
        dev.serial,
        &dev.serial[4..]
    )
}

fn hsrp_brief(dev: &Dev) -> String {
    let groups: Vec<&Iface> = dev.ifaces.iter().filter(|i| i.hsrp.is_some()).collect();
    if groups.is_empty() {
        return String::new();
    }
    let mut s = String::from(
        "                     P indicates configured to preempt.\n                     |\nInterface   Grp  Pri P State   Active          Standby         Virtual IP\n",
    );
    for i in groups {
        let h = i.hsrp.as_ref().expect("a group");
        let (state, active, standby) = if h.active {
            ("Active", "local".to_string(), h.peer.to_string())
        } else {
            ("Standby", h.peer.to_string(), "local".to_string())
        };
        let _ = writeln!(
            s,
            "{:<11} {:<4} {:<3} P {:<7} {:<15} {:<15} {}",
            short(&i.name),
            h.group,
            h.priority,
            state,
            active,
            standby,
            h.vip
        );
    }
    s
}

fn hsrp_detail(dev: &Dev) -> String {
    let mut s = String::new();
    for i in &dev.ifaces {
        let Some(h) = &i.hsrp else { continue };
        let vmac = dotted(hsrp_mac(h.group));
        let _ = writeln!(s, "{} - Group {}", i.name, h.group);
        if h.active {
            let _ = writeln!(
                s,
                "  State is Active\n    2 state changes, last state change 5w6d\n  Virtual IP address is {}\n  Active virtual MAC address is {vmac} (MAC In Use)\n    Local virtual MAC address is {vmac} (v1 default)\n  Hello time 3 sec, hold time 10 sec\n    Next hello sent in 1.264 secs\n  Preemption enabled\n  Active router is local\n  Standby router is {}, priority 100 (expires in 9.808 sec)\n  Priority {} (configured {})\n  Group name is \"hsrp-{}-{}\" (default)",
                h.vip,
                h.peer,
                h.priority,
                h.priority,
                short(&i.name),
                h.group
            );
        } else {
            let _ = writeln!(
                s,
                "  State is Standby\n    1 state change, last state change 5w6d\n  Virtual IP address is {}\n  Active virtual MAC address is {vmac} (MAC Not In Use)\n    Local virtual MAC address is {vmac} (v1 default)\n  Hello time 3 sec, hold time 10 sec\n    Next hello sent in 0.512 secs\n  Preemption enabled\n  Active router is {}, priority 110 (expires in 8.112 sec)\n  Standby router is local\n  Priority {} (configured {})\n  Group name is \"hsrp-{}-{}\" (default)",
                h.vip,
                h.peer,
                h.priority,
                h.priority,
                short(&i.name),
                h.group
            );
        }
    }
    s
}

fn mac_table(t: &Tables, d: usize) -> String {
    let mut s = String::from(
        "          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n All    0100.0ccc.cccc    STATIC      CPU\n All    0100.0ccc.cccd    STATIC      CPU\n",
    );
    for m in &t.macs[d] {
        let _ = writeln!(
            s,
            "{:>4}    {}    DYNAMIC     {}",
            m.vlan,
            dotted(m.mac),
            short(&m.port)
        );
    }
    let _ = writeln!(
        s,
        "Total Mac Addresses for this criterion: {}",
        t.macs[d].len() + 2
    );
    s
}

fn spanning_tree(e: &Estate, t: &Tables, d: usize) -> String {
    let dev = &e.devs[d];
    let mut s = String::new();
    for (v, ports) in &t.stp[d] {
        let root_port = ports.iter().find(|p| p.root);
        let prio = dev.stp_priority + u32::from(*v);
        let root = e
            .devs
            .iter()
            .filter(|x| x.site == dev.site && x.os == Os::Iosxe && x.has_vlan(*v))
            .min_by_key(|x| (x.stp_priority, x.base_mac))
            .expect("a root");
        let _ = writeln!(s, "\nVLAN{v:04}\n  Spanning tree enabled protocol rstp");
        let _ = writeln!(
            s,
            "  Root ID    Priority    {}\n             Address     {}",
            root.stp_priority + u32::from(*v),
            dotted(root.base_mac)
        );
        match root_port {
            Some(p) => {
                let _ = writeln!(
                    s,
                    "             Cost        2\n             Port        1 ({})",
                    p.port
                );
            }
            None => s.push_str("             This bridge is the root\n"),
        }
        let _ = writeln!(
            s,
            "             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n\n  Bridge ID  Priority    {prio}  (priority {} sys-id-ext {v})\n             Address     {}\n             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec\n             Aging Time  300 sec\n\nInterface           Role Sts Cost      Prio.Nbr Type\n------------------- ---- --- --------- -------- --------------------------------",
            dev.stp_priority,
            dotted(dev.base_mac)
        );
        for (n, p) in ports.iter().enumerate() {
            let (role, sts) = if p.blocked {
                ("Altn", "BLK")
            } else if p.root {
                ("Root", "FWD")
            } else {
                ("Desg", "FWD")
            };
            let _ = writeln!(
                s,
                "{:<19} {role} {sts} {:<9} 128.{:<4} P2p{}",
                short(&p.port),
                if p.edge { 4 } else { 2 },
                n + 1,
                if p.edge { " Edge" } else { "" }
            );
        }
    }
    s
}

fn vlans(dev: &Dev) -> String {
    let mut s = String::from(
        "\nVLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n1    default                          active    \n",
    );
    for v in &dev.vlans {
        let ports: Vec<String> = dev
            .ifaces
            .iter()
            .filter(|i| i.mode == Mode::Access(v.id))
            .map(|i| short(&i.name))
            .collect();
        let _ = writeln!(
            s,
            "{:<4} {:<32} active    {}",
            v.id,
            v.name,
            ports.join(", ")
        );
    }
    s.push_str("1002 fddi-default                     act/unsup \n1003 token-ring-default               act/unsup \n1004 fddinet-default                  act/unsup \n1005 trnet-default                    act/unsup \n");
    s
}

fn bgp_summary(dev: &Dev) -> String {
    let Some(bgp) = &dev.bgp else {
        return "% BGP not active\n".to_string();
    };
    let mut s = format!(
        "BGP router identifier {}, local AS number {}\nBGP table version is 14, main routing table version 14\n3 network entries using 744 bytes of memory\n3 path entries using 408 bytes of memory\n2/2 BGP path/bestpath attribute entries using 576 bytes of memory\n1 BGP AS-PATH entries using 24 bytes of memory\n0 BGP route-map cache entries using 0 bytes of memory\n0 BGP filter-list cache entries using 0 bytes of memory\nBGP using 1752 total bytes of memory\nBGP activity 3/0 prefixes, 3/0 paths, scan interval 60 secs\n3 networks peaked at 09:12:44 Sep 21 2026 (5w6d ago)\n\nNeighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n",
        bgp.router_id, bgp.asn
    );
    for n in &bgp.neighbors {
        if n.up {
            let _ = writeln!(
                s,
                "{:<15} 4 {:>12}   58211   58190       14    0    0 5w6d            1",
                n.addr.to_string(),
                n.remote_as
            );
        } else {
            let _ = writeln!(
                s,
                "{:<15} 4 {:>12}   58211   58190        1    0    0 00:12:40 Idle",
                n.addr.to_string(),
                n.remote_as
            );
        }
    }
    s
}

/// The reply of each section of a device, by section name, and the reply
/// of the ARP table of each VRF, by VRF.
pub fn render(
    e: &Estate,
    t: &Tables,
    d: usize,
) -> (BTreeMap<&'static str, String>, BTreeMap<String, String>) {
    let dev = &e.devs[d];
    let sw = switch(dev);
    let l2 = |f: String| if sw { f } else { INVALID.to_string() };
    let mut out = BTreeMap::new();
    out.insert("config", config(dev));
    out.insert("version", version(dev));
    out.insert("interfaces", interfaces(dev));
    out.insert("lldp", lldp(e, d));
    out.insert("cdp", NO_CDP.to_string());
    out.insert("vrfs", vrfs(dev));
    out.insert("rib", rib(dev, &t.ribs[d], true));
    out.insert("rib_global", rib(dev, &t.ribs[d], false));
    out.insert("arp", arp_rows(dev, t, d, "default"));
    out.insert("acls", String::new());
    out.insert("inventory", inventory(dev));
    out.insert("hsrp", hsrp_brief(dev));
    out.insert("vrrp", String::new());
    out.insert("mac_table", l2(mac_table(t, d)));
    out.insert("spanning_tree", l2(spanning_tree(e, t, d)));
    out.insert("vlans", l2(vlans(dev)));
    out.insert("hsrp_detail", hsrp_detail(dev));
    out.insert("vrrp_detail", String::new());
    out.insert("bgp_sessions", bgp_summary(dev));
    super::ospf::cisco(e, d, "", "1", &mut out);
    let mut vrfs = BTreeMap::new();
    if dev.ifaces.iter().any(|i| i.mode == Mode::Mgmt) {
        let v = mgmt_vrf(dev);
        vrfs.insert(v.to_string(), arp_rows(dev, t, d, v));
    }
    (out, vrfs)
}

#[cfg(test)]
mod tests {
    use super::super::route::Path;
    use super::*;

    #[test]
    fn an_ospf_route_shows_the_metric_of_the_calculation() {
        let r = Route {
            vrf: "default".to_string(),
            prefix: (Ipv4Addr::new(198, 51, 100, 0), 24),
            kind: Kind::Ospf,
            metric: 20,
            paths: vec![Path {
                next_hop: Some(Ipv4Addr::new(192, 0, 2, 1)),
                iface: Some("GigabitEthernet1".to_string()),
                vxlan: None,
            }],
        };
        assert!(
            line(&r, "").contains("[110/20] via 192.0.2.1"),
            "{}",
            line(&r, "")
        );
    }
}
