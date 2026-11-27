//! A synthetic OSPF triangle of the NX-OS switches r1, r2 and r3, with
//! their running configs, LLDP sections and collected rows. Each switch has
//! a routed port to each other switch, with the OSPF cost 10, and a LAN on
//! `Ethernet1/3`:
//!
//! | Link | End | End |
//! |---|---|---|
//! | 198.51.100.0/30 | r1 Ethernet1/1 .1 | r2 Ethernet1/1 .2 |
//! | 198.51.100.4/30 | r1 Ethernet1/2 .5 | r3 Ethernet1/1 .6 |
//! | 198.51.100.8/30 | r2 Ethernet1/2 .9 | r3 Ethernet1/2 .10 |
//!
//! The LAN of rN is 203.0.113.0/26, 203.0.113.64/26 or 203.0.113.128/26,
//! with the address .1, .65 or .129 and a host at .10, .74 or .138. r1 also
//! has the collected BGP route 192.0.2.128/25 through r2.

#![allow(dead_code)]

/// One collected route row: the prefix, the protocol, the next hop and the
/// interface, in the VRF `default`.
pub type RouteRow = (String, String, Option<String>, Option<String>);

/// One switch of the triangle.
pub struct Device {
    pub name: String,
    pub config: String,
    pub lldp: String,
    pub routes: Vec<RouteRow>,
    /// The interface and the MAC of each port.
    pub links: Vec<(String, String)>,
    /// The interface, the address and the MAC of each ARP row.
    pub arp: Vec<(String, String, String)>,
}

/// The MAC of the port `Ethernet1/<port>` of switch `n`.
pub fn mac(n: usize, port: usize) -> String {
    format!("00:00:5e:00:53:{n}{port}")
}

/// One end of a link: the switch, the port, the address of the port.
struct End(usize, usize, &'static str);

/// The links with their networks.
const LINKS: [(&str, End, End); 3] = [
    (
        "198.51.100.0/30",
        End(1, 1, "198.51.100.1"),
        End(2, 1, "198.51.100.2"),
    ),
    (
        "198.51.100.4/30",
        End(1, 2, "198.51.100.5"),
        End(3, 1, "198.51.100.6"),
    ),
    (
        "198.51.100.8/30",
        End(2, 2, "198.51.100.9"),
        End(3, 2, "198.51.100.10"),
    ),
];

/// The LAN network, the address of the switch and the host of switch `n`.
fn lan(n: usize) -> (String, String, String) {
    let base = 64 * (n - 1);
    (
        format!("203.0.113.{base}/26"),
        format!("203.0.113.{}", base + 1),
        format!("203.0.113.{}", base + 10),
    )
}

fn s(x: &str) -> String {
    x.to_string()
}

/// The 3 switches. With `mismatch`, the collected route of r1 to the LAN of
/// r2 goes through r3, and the computed route goes through r2.
pub fn devices(mismatch: bool) -> Vec<Device> {
    (1..=3).map(|n| device(n, mismatch)).collect()
}

fn device(n: usize, mismatch: bool) -> Device {
    let name = format!("r{n}");
    // The own ports: the port, the address, the network, the far switch,
    // the far port and the far address.
    let mut ports = Vec::new();
    for (net, a, b) in &LINKS {
        if a.0 == n {
            ports.push((a.1, a.2, *net, b.0, b.1, b.2));
        } else if b.0 == n {
            ports.push((b.1, b.2, *net, a.0, a.1, a.2));
        }
    }
    let (lan_net, lan_addr, lan_host) = lan(n);
    let mut config = format!("hostname {name}\nfeature ospf\n");
    for (port, addr, net, ..) in &ports {
        let len = net.split('/').nth(1).unwrap();
        config.push_str(&format!(
            "interface Ethernet1/{port}\n  no switchport\n  ip address {addr}/{len}\n  ip ospf network point-to-point\n  ip ospf cost 10\n  ip router ospf 1 area 0.0.0.0\n  no shutdown\n"
        ));
    }
    config.push_str(&format!(
        "interface Ethernet1/3\n  no switchport\n  ip address {lan_addr}/26\n  ip ospf cost 10\n  ip router ospf 1 area 0.0.0.0\n  no shutdown\nrouter ospf 1\n  router-id 192.0.2.{n}\n"
    ));
    let rows: Vec<String> = ports
        .iter()
        .map(|(port, _, _, far, far_port, _)| {
            format!(
                r#"{{"l_port_id":"Eth1/{port}","sys_name":"r{far}","chassis_id":"0000.5e00.53{far}0","port_id":"Ethernet1/{far_port}"}}"#
            )
        })
        .collect();
    let lldp = format!(
        r#"{{"TABLE_nbor_detail":{{"ROW_nbor_detail":[{}]}}}}"#,
        rows.join(",")
    );
    let iface = |p: usize| format!("Ethernet1/{p}");
    let mut routes: Vec<RouteRow> = Vec::new();
    for (port, addr, net, ..) in &ports {
        routes.push((s(net), s("direct"), None, Some(iface(*port))));
        routes.push((format!("{addr}/32"), s("local"), None, Some(iface(*port))));
    }
    routes.push((lan_net, s("direct"), None, Some(iface(3))));
    routes.push((format!("{lan_addr}/32"), s("local"), None, Some(iface(3))));
    // The LAN of each other switch through the link to it.
    for (port, _, _, far, _, far_addr) in &ports {
        let mut via = (s(far_addr), iface(*port));
        if mismatch && n == 1 && *far == 2 {
            let (p, _, _, _, _, a) = ports.iter().find(|x| x.3 == 3).unwrap();
            via = (s(a), iface(*p));
        }
        routes.push((lan(*far).0, s("ospf-1"), Some(via.0), Some(via.1)));
    }
    // The link of the 2 other switches through both links.
    let (other, ..) = LINKS.iter().find(|(_, a, b)| a.0 != n && b.0 != n).unwrap();
    for (port, _, _, _, _, far_addr) in &ports {
        routes.push((s(other), s("ospf-1"), Some(s(far_addr)), Some(iface(*port))));
    }
    if n == 1 {
        routes.push((
            s("192.0.2.128/25"),
            s("bgp-64500"),
            Some(s("198.51.100.2")),
            Some(iface(1)),
        ));
    }
    let mut links: Vec<(String, String)> = ports
        .iter()
        .map(|(port, ..)| (iface(*port), mac(n, *port)))
        .collect();
    links.push((iface(3), mac(n, 3)));
    let mut arp: Vec<(String, String, String)> = ports
        .iter()
        .map(|(port, _, _, far, far_port, far_addr)| {
            (iface(*port), s(far_addr), mac(*far, *far_port))
        })
        .collect();
    arp.push((iface(3), lan_host, format!("00:00:5e:00:53:a{n}")));
    Device {
        name,
        config,
        lldp,
        routes,
        links,
        arp,
    }
}
