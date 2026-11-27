//! The replies of an IOS-XR router, each as text with the time line of
//! IOS-XR first.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::model::*;
use super::nxos::system_description;
use super::route::{Kind, Route, Tables};

/// The time line that IOS-XR prints before each answer.
const TIME: &str = "Mon Nov  2 08:00:00.000 UTC\n";

/// The short name of an interface.
fn short(name: &str) -> String {
    for (long, s) in [("TenGigE", "Te"), ("Loopback", "Lo")] {
        if let Some(r) = name.strip_prefix(long) {
            return format!("{s}{r}");
        }
    }
    name.to_string()
}

fn config(dev: &Dev) -> String {
    let mut s = format!(
        "{TIME}Building configuration...\n!! IOS XR Configuration {v}\n!! Last configuration change at Mon Nov  2 07:30:00 2026 by admin\n!\nhostname {n}\nclock timezone UTC 0\nlogging console disabled\nlogging buffered 1000000\ndomain name demo.example\nusername admin\n group root-lr\n group cisco-support\n secret 10 $6$DEMOSALT$FAKEHASHFAKEHASH\n!\nvrf MGMT\n address-family ipv4 unicast\n !\n!\nline default\n transport input ssh\n!\nsnmp-server community FAKECOMMUNITY RO\nntp\n server vrf MGMT 10.255.{site}.5\n!\n",
        v = dev.version,
        n = dev.name,
        site = dev.site + 1
    );
    for i in &dev.ifaces {
        let _ = writeln!(s, "interface {}", i.name);
        if !i.desc.is_empty() && i.mode != Mode::Mgmt {
            let _ = writeln!(s, " description {}", i.desc);
        }
        if i.vrf != "default" {
            let _ = writeln!(s, " vrf {}", i.vrf);
        }
        if i.mode == Mode::Routed {
            s.push_str(" mtu 9216\n");
        }
        if let Some((a, l)) = i.addr {
            let _ = writeln!(s, " ipv4 address {a} {}", mask(l));
        }
        if i.mode == Mode::Routed {
            s.push_str(" load-interval 30\n");
        }
        s.push_str("!\n");
    }
    s.push_str("route-policy PASS\n  pass\nend-policy\n!\n");
    let mut statics: BTreeMap<&str, Vec<&Static>> = BTreeMap::new();
    for st in &dev.statics {
        statics.entry(st.vrf.as_str()).or_default().push(st);
    }
    if !statics.is_empty() {
        s.push_str("router static\n");
        for (vrf, list) in statics {
            let _ = writeln!(s, " vrf {vrf}\n  address-family ipv4 unicast");
            for st in list {
                let _ = writeln!(s, "   {}/{} {}", st.prefix.0, st.prefix.1, st.next_hop);
            }
            s.push_str("  !\n !\n");
        }
        s.push_str("!\n");
    }
    if let Some(bgp) = &dev.bgp {
        let _ = writeln!(s, "router ospf CORE\n router-id {}", bgp.router_id);
        if dev.ospf_redistribute_bgp {
            let _ = writeln!(s, " redistribute bgp {}", bgp.asn);
        }
        s.push_str(" area 0\n");
        for i in dev.ifaces.iter().filter(|i| i.ospf) {
            let _ = writeln!(s, "  interface {}\n   cost {}", i.name, i.ospf_cost);
            if i.mode != Mode::Loopback {
                s.push_str("   network point-to-point\n");
            }
            if i.mode == Mode::Loopback || i.ospf_passive {
                s.push_str("   passive enable\n");
            }
            s.push_str("  !\n");
        }
        s.push_str(" !\n!\n");
        let _ = writeln!(
            s,
            "router bgp {}\n bgp router-id {}\n address-family ipv4 unicast\n !",
            bgp.asn, bgp.router_id
        );
        for n in &bgp.neighbors {
            let _ = writeln!(
                s,
                " neighbor {}\n  remote-as {}\n  description {}",
                n.addr, n.remote_as, n.desc
            );
            if let Some(src) = &n.update_source {
                let _ = writeln!(s, "  update-source {src}");
            }
            s.push_str("  address-family ipv4 unicast\n");
            if n.remote_as == bgp.asn {
                s.push_str("   next-hop-self\n");
            } else {
                s.push_str("   route-policy PASS in\n   route-policy PASS out\n");
            }
            s.push_str("  !\n !\n");
        }
        s.push_str("!\n");
    }
    s.push_str("ssh server v2\nssh server vrf MGMT\nend\n");
    s
}

fn version(dev: &Dev) -> String {
    format!(
        "{TIME}Cisco IOS XR Software, Version {v}\nCopyright (c) 2013-2026 by Cisco Systems, Inc.\n\nBuild Information:\n Built By     : demo\n Built On     : Thu Jan 15 10:00:00 UTC 2026\n Build Host   : demo-build\n Workspace    : /demo/workspace\n Version      : {v}\n Label        : {v}\n\ncisco {m} (Intel 8 core CPU) processor with 32GB of memory\n{n} uptime is 5 weeks, 6 days, 3 hours, 12 minutes\n",
        v = dev.version,
        m = dev.model,
        n = dev.name
    )
}

fn interfaces(dev: &Dev) -> String {
    let mut s = TIME.to_string();
    for i in &dev.ifaces {
        let _ = writeln!(
            s,
            "{} is up, line protocol is up\n  Interface state transitions: 1",
            i.name
        );
        let hw = match i.mode {
            Mode::Loopback => "Loopback interface(s)",
            Mode::Mgmt => "Management Ethernet",
            _ => "TenGigE",
        };
        match i.mac {
            Some(m) => {
                let _ = writeln!(
                    s,
                    "  Hardware is {hw}, address is {} (bia {})",
                    dotted(m),
                    dotted(m)
                );
            }
            None => {
                let _ = writeln!(s, "  Hardware is {hw}");
            }
        }
        if !i.desc.is_empty() {
            let _ = writeln!(s, "  Description: {}", i.desc);
        }
        match i.addr {
            Some((a, l)) => {
                let _ = writeln!(s, "  Internet address is {a}/{l}");
            }
            None => s.push_str("  Internet address is Unknown\n"),
        }
        match i.mode {
            Mode::Loopback => s.push_str("  MTU 1500 bytes, BW 0 Kbit\n     reliability Unknown, txload Unknown, rxload Unknown\n  Encapsulation Loopback,  loopback not set,\n"),
            Mode::Mgmt => s.push_str("  MTU 1514 bytes, BW 1000000 Kbit (Max: 1000000 Kbit)\n     reliability 255/255, txload 0/255, rxload 0/255\n  Encapsulation ARPA,\n  Full-duplex, 1000Mb/s, 1000BASE-T, link type is autonegotiation\n"),
            _ => s.push_str("  MTU 9216 bytes, BW 10000000 Kbit (Max: 10000000 Kbit)\n     reliability 255/255, txload 1/255, rxload 1/255\n  Encapsulation ARPA,\n  Full-duplex, 10000Mb/s, 10GBASE-LR, link type is force-up\n  Last link flapped 5w6d\n  Last input 00:00:00, output 00:00:00\n  5 minute input rate 2412000 bits/sec, 512 packets/sec\n  5 minute output rate 2298000 bits/sec, 498 packets/sec\n"),
        }
        s.push('\n');
    }
    s
}

fn lldp(e: &Estate, d: usize) -> String {
    let dev = &e.devs[d];
    let mut s = format!(
        "{TIME}Capability codes:\n        (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n        (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n\n"
    );
    let mut n = 0;
    for i in &dev.ifaces {
        let Some((f, fport)) = e.far(d, &i.name) else {
            continue;
        };
        let fd = &e.devs[f];
        let fi = fd.iface(&fport);
        let port_id = match fd.os {
            Os::Iosxe => super::iosxe::short(&fport),
            _ => fport.clone(),
        };
        let _ = write!(
            s,
            "------------------------------------------------\nLocal Interface: {}\nChassis id: {}\nPort id: {port_id}\nPort Description: {}\nSystem Name: {}\n\nSystem Description: \n{}\n\nTime remaining: 101 seconds\nHold Time: 120 seconds\nSystem Capabilities: B,R\nEnabled Capabilities: R\nManagement Addresses:\n  IPv4 address: {}\nPeer MAC Address: {}\n\n",
            i.name,
            dotted(fd.base_mac),
            if fi.desc.is_empty() {
                "-"
            } else {
                fi.desc.as_str()
            },
            fd.name,
            system_description(fd),
            fd.mgmt,
            colon(fi.mac.unwrap_or(fd.base_mac))
        );
        n += 1;
    }
    let _ = writeln!(s, "Total entries displayed: {n}");
    s
}

fn vrfs(dev: &Dev) -> String {
    let m = dev
        .ifaces
        .iter()
        .find(|i| i.mode == Mode::Mgmt)
        .map_or(String::new(), |i| i.name.clone());
    format!(
        "{TIME}\nVRF MGMT; RD not set; VPN ID not set\nVRF mode: Regular\nDescription not set\nInterfaces:\n  {m}\nAddress family IPV4 Unicast\n  No import VPN route-target communities\n  No export VPN route-target communities\n  No import route policy\n  No export route policy\n"
    )
}

const CODES: &str = "Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP
       i - ISIS, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, su - IS-IS summary null, * - candidate default
       U - per-user static route, o - ODR, L - local, G  - DAGR, l - LISP
       A - access/subscriber, a - Application route
       M - mobile route, r - RPL, t - Traffic Engineering, (!) - FRR Backup path
";

fn route_lines(r: &Route) -> String {
    let default = r.prefix.1 == 0;
    let code = match (r.kind, default) {
        (Kind::Connected, _) => "C",
        (Kind::Local, _) => "L",
        (Kind::Static, true) => "S*",
        (Kind::Static, false) => "S",
        (Kind::Ospf, true) => "O*E2",
        (Kind::Ospf, false) if r.external => "O E2",
        (Kind::Ospf, false) => "O",
        (Kind::Ebgp | Kind::Ibgp, true) => "B*",
        (Kind::Ebgp | Kind::Ibgp, false) => "B",
    };
    let head = format!("{code:<4} {}/{}", r.prefix.0, r.prefix.1);
    let mut s = String::new();
    match r.kind {
        Kind::Connected | Kind::Local => {
            let _ = writeln!(
                s,
                "{head} is directly connected, 5w6d, {}",
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
            let indent = " ".repeat(head.len() + 1);
            for (n, p) in r.paths.iter().enumerate() {
                let nh = p.next_hop.expect("a next hop");
                let tail = match (k, &p.iface) {
                    (Kind::Ospf, Some(i)) => format!(", 5w6d, {i}"),
                    _ => ", 5w6d".to_string(),
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

fn rib(routes: &[Route]) -> String {
    let mut by_vrf: BTreeMap<&str, Vec<&Route>> = BTreeMap::new();
    for r in routes {
        by_vrf.entry(r.vrf.as_str()).or_default().push(r);
    }
    let mut s = TIME.to_string();
    for (vrf, rs) in by_vrf {
        let _ = write!(s, "\nVRF: {vrf}\n\n{CODES}\n");
        match rs.iter().find(|r| r.prefix.1 == 0) {
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
        for r in rs {
            s.push_str(&route_lines(r));
        }
    }
    s
}

fn arp(dev: &Dev, t: &Tables, d: usize) -> String {
    let mut s = TIME.to_string();
    let head = "Address         Age        Hardware Addr   State      Type  Interface\n";
    let rule = "-------------------------------------------------------------------------------\n";
    for (node, mgmt) in [("0/RP0/CPU0", true), ("0/0/CPU0", false)] {
        let _ = write!(s, "\n{rule}{node}\n{rule}{head}");
        for a in &t.arp[d] {
            let i = dev.iface(&a.iface);
            if (i.mode == Mode::Mgmt) != mgmt {
                continue;
            }
            let (age, state) = if a.own {
                ("-", "Interface")
            } else {
                ("00:04:12", "Dynamic")
            };
            let name = if mgmt {
                a.iface.clone()
            } else {
                short(&a.iface)
            };
            let _ = writeln!(
                s,
                "{:<15} {:<10} {}  {:<10} ARPA  {name}",
                a.ip.to_string(),
                age,
                dotted(a.mac),
                state
            );
        }
    }
    s
}

fn inventory(dev: &Dev) -> String {
    format!(
        "{TIME}NAME: \"Rack 0\", DESCR: \"{m} 1RU Chassis\"\nPID: {m}, VID: V02, SN: {sn}\n\nNAME: \"0/RP0/CPU0\", DESCR: \"{m} Route Processor\"\nPID: {m}-RP, VID: V02, SN: {sn}R\n",
        m = dev.model,
        sn = dev.serial
    )
}

fn bgp_summary(dev: &Dev) -> String {
    let Some(bgp) = &dev.bgp else {
        return format!("{TIME}% BGP instance 'default' not active\n");
    };
    let mut s = format!(
        "{TIME}BGP router identifier {}, local AS number {}\nBGP generic scan interval 60 secs\nNon-stop routing is enabled\nBGP table state: Active\nTable ID: 0xe0000000   RD version: 214\nBGP main routing table version 214\nBGP NSR Initial initsync version 4 (Reached)\nBGP NSR/ISSU Sync-Group versions 0/0\nBGP scan interval 60 secs\n\nBGP is operating in STANDALONE mode.\n\n\nProcess       RcvTblVer   bRIB/RIB   LabelVer  ImportVer  SendTblVer  StandbyVer\nSpeaker             214        214        214        214         214           0\n\nNeighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd\n",
        bgp.router_id, bgp.asn
    );
    for n in &bgp.neighbors {
        let _ = writeln!(
            s,
            "{:<15}   0 {:>5}   58211   58190      214    0    0 5w6d             12",
            n.addr.to_string(),
            n.remote_as
        );
    }
    s
}

/// The reply of each section of a router, by section name.
pub fn render(e: &Estate, t: &Tables, d: usize) -> BTreeMap<&'static str, String> {
    let dev = &e.devs[d];
    let mut out = BTreeMap::new();
    out.insert("config", config(dev));
    out.insert("version", version(dev));
    out.insert("interfaces", interfaces(dev));
    out.insert("lldp", lldp(e, d));
    out.insert("cdp", format!("{TIME}% CDP is not enabled\n"));
    out.insert("vrfs", vrfs(dev));
    out.insert("rib", rib(&t.ribs[d]));
    out.insert("arp", arp(dev, t, d));
    out.insert("inventory", inventory(dev));
    out.insert("hsrp", TIME.to_string());
    out.insert("bgp_sessions", bgp_summary(dev));
    super::ospf::cisco(e, d, TIME, "CORE", &t.redistributed, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::route::Path;
    use super::*;

    #[test]
    fn an_ospf_route_shows_the_metric_of_the_calculation() {
        let r = Route {
            vrf: "default".to_string(),
            prefix: (Ipv4Addr::new(198, 51, 100, 0), 24),
            kind: Kind::Ospf,
            external: false,
            metric: 20,
            paths: vec![Path {
                next_hop: Some(Ipv4Addr::new(192, 0, 2, 1)),
                iface: Some("TenGigE0/0/0/0".to_string()),
                vxlan: None,
            }],
        };
        let text = route_lines(&r);
        assert!(text.contains("[110/20] via 192.0.2.1"), "{text}");
        let e2 = route_lines(&Route {
            external: true,
            ..r
        });
        assert!(e2.starts_with("O E2 198.51.100.0/24 [110/20]"), "{e2}");
    }
}
