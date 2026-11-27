//! The replies of an NX-OS switch: the running config as text and the
//! other sections as the JSON of `| json`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};

use super::model::*;
use super::route::{Kind, Route, Tables};

/// The answer of a switch to a command of a feature that it does not run.
pub const NO_FEATURE: &str = "% Invalid command at '^' marker.\n";

/// The answer of a switch with no CDP.
const NO_CDP: &str = "Note: CDP not enabled\n";

/// The short name of an interface, as `show` tables print it.
pub fn short(name: &str) -> String {
    if let Some(r) = name.strip_prefix("Ethernet") {
        format!("Eth{r}")
    } else if let Some(r) = name.strip_prefix("port-channel") {
        format!("Po{r}")
    } else if let Some(r) = name.strip_prefix("loopback") {
        format!("Lo{r}")
    } else {
        name.to_string()
    }
}

pub fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("JSON");
    s.push('\n');
    s
}

/// A list of VLANs in the form `10,20,3001`.
pub fn vlan_list(v: &[u16]) -> String {
    v.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
}

fn config(e: &Estate, d: usize) -> String {
    let dev = &e.devs[d];
    let mut s = String::new();
    let n = &dev.name;
    let leaf = dev.l3vni.is_some();
    let _ = writeln!(
        s,
        "!Command: show running-config\n!Running configuration last done at: Mon Nov  2 07:30:00 2026\n!Time: Mon Nov  2 08:00:00 2026\n"
    );
    let _ = writeln!(s, "version {} Bios:version 05.47", dev.version);
    let _ = writeln!(s, "hostname {n}");
    let _ = writeln!(
        s,
        "vdc {n} id 1\n  limit-resource vlan minimum 16 maximum 4094\n  limit-resource vrf minimum 2 maximum 4096\n"
    );
    if leaf {
        s.push_str("nv overlay evpn\n");
    }
    let mut features = vec!["ospf", "bgp", "lldp"];
    if leaf {
        features.extend([
            "interface-vlan",
            "vn-segment-vlan-based",
            "lacp",
            "vpc",
            "nv overlay",
            "fabric forwarding",
        ]);
    }
    features.sort();
    for f in features {
        let _ = writeln!(s, "feature {f}");
    }
    let _ = writeln!(
        s,
        "\nusername admin password 5 $5$DEMOSALT$FAKEHASHFAKEHASHFAKEHASH  role network-admin\nip domain-lookup\nip domain-name demo.example\ncopp profile strict\nsnmp-server community FAKECOMMUNITY group network-operator\nntp server 10.255.{}.5 use-vrf management\n",
        dev.site + 1
    );
    if leaf {
        let _ = writeln!(
            s,
            "fabric forwarding anycast-gateway-mac {}",
            dotted(ANYCAST_MAC)
        );
    }
    for acl in &dev.acls {
        let _ = writeln!(s, "ip access-list {}", acl.name);
        for (seq, text) in &acl.entries {
            let _ = writeln!(s, "  {seq} {text}");
        }
    }
    if !dev.vlans.is_empty() {
        let ids: Vec<u16> = std::iter::once(1)
            .chain(dev.vlans.iter().map(|v| v.id))
            .collect();
        let _ = writeln!(s, "vlan {}", vlan_list(&ids));
        for v in &dev.vlans {
            let _ = writeln!(s, "vlan {}\n  name {}", v.id, v.name);
            if let Some(vni) = v.vni {
                let _ = writeln!(s, "  vn-segment {vni}");
            }
        }
        s.push('\n');
    }
    if let Some((vrf, vni, _)) = &dev.l3vni {
        let _ = writeln!(
            s,
            "vrf context {vrf}\n  vni {vni}\n  rd auto\n  address-family ipv4 unicast\n    route-target both auto\n    route-target both auto evpn"
        );
    }
    let _ = writeln!(s, "vrf context management");
    for st in dev.statics.iter().filter(|x| x.vrf == "management") {
        let _ = writeln!(
            s,
            "  ip route {}/{} {}",
            st.prefix.0, st.prefix.1, st.next_hop
        );
    }
    if let (Some(domain), Some(peer)) = (dev.vpc_domain, dev.vpc_peer) {
        let _ = writeln!(
            s,
            "vpc domain {domain}\n  peer-switch\n  role priority {}\n  peer-keepalive destination {} source {}\n  delay restore 150\n  peer-gateway\n  auto-recovery\n  ip arp synchronize",
            if peer > d { 100 } else { 200 },
            e.devs[peer].mgmt,
            dev.mgmt
        );
    }
    s.push('\n');
    for i in &dev.ifaces {
        let _ = writeln!(s, "interface {}", i.name);
        if !i.desc.is_empty() && i.mode != Mode::Nve {
            let _ = writeln!(s, "  description {}", i.desc);
        }
        match &i.mode {
            Mode::Svi(_) => {
                s.push_str("  no shutdown\n");
                if i.ip_forward {
                    s.push_str("  mtu 9216\n");
                }
                if i.vrf != "default" {
                    let _ = writeln!(s, "  vrf member {}", i.vrf);
                }
                if i.ip_forward {
                    s.push_str("  ip forward\n");
                }
                if let Some((a, l)) = i.addr {
                    let _ = writeln!(s, "  ip address {a}/{l}");
                }
                if i.anycast {
                    s.push_str("  fabric forwarding mode anycast-gateway\n");
                }
            }
            Mode::PortChannel(v) => {
                let _ = writeln!(
                    s,
                    "  switchport\n  switchport mode trunk\n  switchport trunk allowed vlan {}\n  spanning-tree port type network",
                    vlan_list(v)
                );
                if i.peer_link {
                    s.push_str("  vpc peer-link\n");
                }
            }
            Mode::Nve => {
                s.push_str(
                    "  no shutdown\n  host-reachability protocol bgp\n  source-interface loopback1\n",
                );
                for v in dev.vlans.iter() {
                    match v.vni {
                        Some(vni) if Some(vni) == dev.l3vni.as_ref().map(|x| x.1) => {
                            let _ = writeln!(s, "  member vni {vni} associate-vrf");
                        }
                        Some(vni) => {
                            let _ = writeln!(
                                s,
                                "  member vni {vni}\n    ingress-replication protocol bgp"
                            );
                        }
                        None => {}
                    }
                }
            }
            Mode::Access(v) => {
                let _ = writeln!(
                    s,
                    "  switchport\n  switchport access vlan {v}\n  spanning-tree port type edge\n  no shutdown"
                );
            }
            Mode::Member(n, v) => {
                let _ = writeln!(
                    s,
                    "  switchport\n  switchport mode trunk\n  switchport trunk allowed vlan {}\n  channel-group {n} mode active\n  no shutdown",
                    vlan_list(v)
                );
            }
            Mode::Routed => {
                s.push_str("  no switchport\n  mtu 9216\n");
                if i.vrf != "default" {
                    let _ = writeln!(s, "  vrf member {}", i.vrf);
                }
                if let Some(acl) = &i.acl_in {
                    let _ = writeln!(s, "  ip access-group {acl} in");
                }
                if let Some((a, l)) = i.addr {
                    let _ = writeln!(s, "  ip address {a}/{l}");
                }
                if i.ospf {
                    let _ = writeln!(s, "  ip ospf cost {}", i.ospf_cost);
                    s.push_str("  ip ospf network point-to-point\n");
                    if i.ospf_passive {
                        s.push_str("  ip ospf passive-interface\n");
                    }
                    s.push_str("  ip router ospf UNDERLAY area 0.0.0.0\n");
                }
                s.push_str("  no shutdown\n");
            }
            Mode::Loopback => {
                if let Some((a, l)) = i.addr {
                    let _ = writeln!(s, "  ip address {a}/{l}");
                }
                if let Some((a, l)) = i.secondary {
                    let _ = writeln!(s, "  ip address {a}/{l} secondary");
                }
                if i.ospf {
                    let _ = writeln!(
                        s,
                        "  ip ospf cost {}\n  ip router ospf UNDERLAY area 0.0.0.0",
                        i.ospf_cost
                    );
                }
            }
            Mode::Mgmt => {
                if let Some((a, l)) = i.addr {
                    let _ = writeln!(s, "  vrf member {}\n  ip address {a}/{l}", i.vrf);
                }
            }
            Mode::Trunk(_) => {}
        }
        s.push('\n');
    }
    s.push_str("line console\nline vty\n");
    let _ = writeln!(
        s,
        "boot nxos bootflash:/nxos64-cs.{}.M.bin",
        dev.version.replace(['(', ')'], ".").trim_end_matches('.')
    );
    let rid = dev.bgp.as_ref().map(|b| b.router_id);
    if let Some(rid) = rid {
        let _ = writeln!(s, "router ospf UNDERLAY\n  router-id {rid}");
    }
    if let Some(bgp) = &dev.bgp {
        let _ = writeln!(
            s,
            "router bgp {}\n  router-id {}\n  log-neighbor-changes\n  address-family l2vpn evpn",
            bgp.asn, bgp.router_id
        );
        if dev.role == Role::Spine {
            s.push_str("    retain route-target all\n");
        }
        for nb in bgp.neighbors.iter().filter(|x| x.vrf == "default") {
            let _ = writeln!(
                s,
                "  neighbor {}\n    remote-as {}\n    description {}",
                nb.addr, nb.remote_as, nb.desc
            );
            if let Some(src) = &nb.update_source {
                let _ = writeln!(s, "    update-source {src}");
            }
            s.push_str("    address-family l2vpn evpn\n      send-community\n      send-community extended\n");
            if nb.rr_client {
                s.push_str("      route-reflector-client\n");
            }
        }
        if let Some((vrf, _, _)) = &dev.l3vni {
            let _ = writeln!(
                s,
                "  vrf {vrf}\n    address-family ipv4 unicast\n      advertise l2vpn evpn"
            );
            for nb in bgp.neighbors.iter().filter(|x| &x.vrf == vrf) {
                let _ = writeln!(
                    s,
                    "    neighbor {}\n      remote-as {}\n      description {}\n      address-family ipv4 unicast",
                    nb.addr, nb.remote_as, nb.desc
                );
            }
        }
    }
    if leaf {
        s.push_str("evpn\n");
        for v in &dev.vlans {
            if let Some(vni) = v.vni
                && Some(vni) != dev.l3vni.as_ref().map(|x| x.1)
            {
                let _ = writeln!(
                    s,
                    "  vni {vni} l2\n    rd auto\n    route-target import auto\n    route-target export auto"
                );
            }
        }
    }
    s
}

fn version(dev: &Dev) -> String {
    pretty(&json!({
        "header_str": "Cisco Nexus Operating System (NX-OS) Software",
        "bios_ver_str": "05.47",
        "nxos_ver_str": dev.version,
        "host_name": dev.name,
        "proc_board_id": dev.serial,
        "chassis_id": format!("Nexus9000 {} chassis", dev.model.trim_start_matches("N9K-")),
        "kern_uptm_days": 41,
        "kern_uptm_hrs": 3,
        "kern_uptm_mins": 12,
        "kern_uptm_secs": 7,
    }))
}

fn speed(mbps: u32) -> String {
    if mbps >= 1000 {
        format!("{} Gb/s", mbps / 1000)
    } else {
        format!("{mbps} Mb/s")
    }
}

fn interfaces(dev: &Dev) -> String {
    let rows: Vec<Value> = dev
        .ifaces
        .iter()
        .map(|i| {
            let mut r = serde_json::Map::new();
            r.insert("interface".into(), json!(i.name));
            match &i.mode {
                Mode::Svi(_) => {
                    r.insert("svi_admin_state".into(), json!("up"));
                    r.insert("svi_line_proto".into(), json!("up"));
                    if let Some(m) = i.mac {
                        r.insert("svi_mac".into(), json!(dotted(m)));
                    }
                    if let Some((a, l)) = i.addr {
                        r.insert("svi_ip_addr".into(), json!(a.to_string()));
                        r.insert("svi_ip_mask".into(), json!(l));
                    }
                    r.insert("svi_desc".into(), json!(i.desc));
                    r.insert(
                        "svi_mtu".into(),
                        json!(if i.ip_forward { 9216 } else { 1500 }),
                    );
                }
                _ => {
                    r.insert("state".into(), json!(if i.up { "up" } else { "down" }));
                    r.insert("admin_state".into(), json!("up"));
                    if let Some(m) = i.mac {
                        r.insert("eth_hw_addr".into(), json!(dotted(m)));
                    }
                    let mode = match &i.mode {
                        Mode::Access(_) => Some("access"),
                        Mode::Trunk(_) | Mode::PortChannel(_) | Mode::Member(..) => Some("trunk"),
                        Mode::Routed => Some("routed"),
                        _ => None,
                    };
                    if let Some(m) = mode {
                        r.insert("eth_mode".into(), json!(m));
                    }
                    if let Some((a, l)) = i.addr {
                        r.insert("eth_ip_addr".into(), json!(a.to_string()));
                        r.insert("eth_ip_mask".into(), json!(l));
                    }
                    if !matches!(i.mode, Mode::Loopback | Mode::Nve) {
                        let mbps = if matches!(i.mode, Mode::PortChannel(_)) {
                            2 * i.speed
                        } else if i.mode == Mode::Mgmt {
                            1000
                        } else {
                            i.speed
                        };
                        r.insert(
                            "eth_mtu".into(),
                            json!(if i.mode == Mode::Mgmt { "1500" } else { "9216" }),
                        );
                        r.insert("eth_speed".into(), json!(speed(mbps)));
                        r.insert("eth_duplex".into(), json!("full"));
                        r.insert("eth_bw".into(), json!(mbps * 1000));
                        r.insert("eth_inpkts".into(), json!(184_220_113u64));
                        r.insert("eth_outpkts".into(), json!(176_904_552u64));
                        r.insert("eth_link_flapped".into(), json!("5week(s) 6day(s)"));
                    }
                    if !i.desc.is_empty() {
                        r.insert("desc".into(), json!(i.desc));
                    }
                }
            }
            Value::Object(r)
        })
        .collect();
    pretty(&json!({"TABLE_interface": {"ROW_interface": rows}}))
}

fn lldp(e: &Estate, d: usize) -> String {
    let dev = &e.devs[d];
    let mut rows = Vec::new();
    for i in &dev.ifaces {
        let Some((f, port)) = e.far(d, &i.name) else {
            continue;
        };
        let fd = &e.devs[f];
        let fi = fd.iface(&port);
        rows.push(json!({
            "l_port_id": short(&i.name),
            "sys_name": fd.name,
            "chassis_id": dotted(fd.base_mac),
            "port_id": port,
            "ttl": 120,
            "sys_desc": system_description(fd),
            "port_desc": if fi.desc.is_empty() { "null".to_string() } else { fi.desc.clone() },
            "mgmt_addr": fd.mgmt.to_string(),
        }));
    }
    if rows.is_empty() {
        return String::new();
    }
    pretty(&json!({"TABLE_nbor_detail": {"ROW_nbor_detail": rows}}))
}

/// The system description that a device sends in LLDP.
pub fn system_description(d: &Dev) -> String {
    match d.os {
        Os::Nxos => format!(
            "Cisco Nexus Operating System (NX-OS) Software {}",
            d.version
        ),
        Os::Iosxe => format!(
            "Cisco IOS Software [Cupertino], {} Software, Version {}",
            d.model, d.version
        ),
        Os::Iosxr => format!("Cisco IOS XR Software, Version {}", d.version),
    }
}

fn vlans(dev: &Dev) -> String {
    let mut rows = vec![json!({
        "vlanshowbr-vlanid": "1",
        "vlanshowbr-vlanname": "default",
        "vlanshowbr-vlanstate": "active",
        "vlanshowbr-shutstate": "noshutdown",
    })];
    for v in &dev.vlans {
        let ports: Vec<String> = dev
            .ifaces
            .iter()
            .filter(|i| match &i.mode {
                Mode::Access(a) => *a == v.id,
                Mode::PortChannel(l) => l.contains(&v.id),
                _ => false,
            })
            .map(|i| i.name.clone())
            .collect();
        let mut r = json!({
            "vlanshowbr-vlanid": v.id.to_string(),
            "vlanshowbr-vlanname": v.name,
            "vlanshowbr-vlanstate": "active",
            "vlanshowbr-shutstate": "noshutdown",
        });
        if !ports.is_empty() {
            r["vlanshowplist-ifidx"] = json!(ports.join(","));
        }
        rows.push(r);
    }
    pretty(&json!({"TABLE_vlanbrief": {"ROW_vlanbrief": rows}}))
}

fn vrfs(dev: &Dev) -> String {
    let mut names = vec!["default".to_string(), "management".to_string()];
    if let Some((v, _, _)) = &dev.l3vni {
        names.push(v.clone());
    }
    let rows: Vec<Value> = names
        .iter()
        .enumerate()
        .map(
            |(i, n)| json!({"vrf_name": n, "vrf_id": i + 1, "vrf_state": "Up", "vrf_reason": "--"}),
        )
        .collect();
    pretty(&json!({"TABLE_vrf": {"ROW_vrf": rows}}))
}

fn client(k: Kind, asn: u32) -> (String, u32) {
    match k {
        Kind::Connected => ("direct".into(), 0),
        Kind::Local => ("local".into(), 0),
        Kind::Static => ("static".into(), 1),
        Kind::Ospf => ("ospf-UNDERLAY".into(), 110),
        Kind::Ebgp => (format!("bgp-{asn}"), 20),
        Kind::Ibgp => (format!("bgp-{asn}"), 200),
    }
}

fn rib(dev: &Dev, routes: &[Route]) -> String {
    let asn = dev.bgp.as_ref().map_or(0, |b| b.asn);
    let mut by_vrf: BTreeMap<&str, Vec<&Route>> = BTreeMap::new();
    for r in routes {
        by_vrf.entry(r.vrf.as_str()).or_default().push(r);
    }
    let vrfs: Vec<Value> = by_vrf
        .iter()
        .map(|(vrf, rs)| {
            let mut prefixes: Vec<Value> = Vec::new();
            for r in rs {
                let (name, pref) = client(r.kind, asn);
                let own = dev
                    .ifaces
                    .iter()
                    .find(|i| Some(i.name.as_str()) == r.paths[0].iface.as_deref())
                    .and_then(|i| i.addr)
                    .map(|x| x.0);
                let paths: Vec<Value> = r
                    .paths
                    .iter()
                    .map(|p| {
                        let mut x = serde_json::Map::new();
                        let nh = match (r.kind, p.next_hop) {
                            (_, Some(n)) => n.to_string(),
                            (Kind::Local, None) => r.prefix.0.to_string(),
                            _ => own.map_or_else(|| "0.0.0.0".into(), |a| a.to_string()),
                        };
                        x.insert("ipnexthop".into(), json!(nh));
                        if let Some(i) = &p.iface {
                            x.insert("ifname".into(), json!(i));
                        }
                        x.insert("uptime".into(), json!("P41DT3H12M"));
                        x.insert("pref".into(), json!(pref));
                        x.insert("metric".into(), json!(r.metric));
                        x.insert("clientname".into(), json!(name));
                        x.insert("ubest".into(), json!("true"));
                        if let Some(vni) = p.vxlan {
                            x.insert("segid".into(), json!(vni));
                            x.insert("tunnelid".into(), json!(format!("0x{:08x}", u32::from(p.next_hop.expect("a tunnel end")))));
                            x.insert("encap".into(), json!("vxlan"));
                        }
                        Value::Object(x)
                    })
                    .collect();
                prefixes.push(json!({
                    "ipprefix": format!("{}/{}", r.prefix.0, r.prefix.1),
                    "ucast-nhops": r.paths.len(),
                    "mcast-nhops": 0,
                    "attached": matches!(r.kind, Kind::Connected | Kind::Local),
                    "TABLE_path": {"ROW_path": paths},
                }));
            }
            json!({
                "vrf-name-out": vrf,
                "TABLE_addrf": {"ROW_addrf": [{"addrf": "ipv4", "TABLE_prefix": {"ROW_prefix": prefixes}}]},
            })
        })
        .collect();
    pretty(&json!({"TABLE_vrf": {"ROW_vrf": vrfs}}))
}

fn mac_table(t: &Tables, d: usize) -> String {
    let rows: Vec<Value> = t.macs[d]
        .iter()
        .map(|m| {
            json!({
                "disp_mac_addr": dotted(m.mac),
                "disp_type": "dynamic",
                "disp_vlan": m.vlan.to_string(),
                "disp_is_static": "disabled",
                "disp_age": "0",
                "disp_is_secure": "disabled",
                "disp_is_ntfy": "disabled",
                "disp_port": short(&m.port),
            })
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    pretty(&json!({"TABLE_mac_address": {"ROW_mac_address": rows}}))
}

fn arp(dev: &Dev, t: &Tables, d: usize) -> String {
    let mut by_vrf: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for a in t.arp[d].iter().filter(|a| !a.own) {
        let vrf = dev.iface(&a.iface).vrf.clone();
        by_vrf.entry(vrf).or_default().push(json!({
            "intf-out": a.iface,
            "ip-addr-out": a.ip.to_string(),
            "time-stamp": "00:04:12",
            "mac": dotted(a.mac),
        }));
    }
    let rows: Vec<Value> = by_vrf
        .into_iter()
        .map(|(vrf, adj)| {
            json!({
                "vrf-name-out": vrf,
                "cnt-total": adj.len(),
                "TABLE_adj": {"ROW_adj": adj},
            })
        })
        .collect();
    pretty(&json!({"TABLE_vrf": {"ROW_vrf": rows}}))
}

fn vrf_interfaces(dev: &Dev) -> String {
    let ids = |v: &str| match v {
        "default" => 1,
        "management" => 2,
        _ => 3,
    };
    let rows: Vec<Value> = dev
        .ifaces
        .iter()
        .filter(|i| i.is_l3() || i.ip_forward || i.mode == Mode::Nve)
        .map(|i| json!({"if_name": i.name, "vrf_name": i.vrf, "vrf_id": ids(&i.vrf), "soo": "--"}))
        .collect();
    pretty(&json!({"TABLE_if": {"ROW_if": rows}}))
}

fn acl(dev: &Dev) -> String {
    if dev.acls.is_empty() {
        return String::new();
    }
    let rows: Vec<Value> = dev
        .acls
        .iter()
        .map(|a| {
            let entries: Vec<Value> = a
                .entries
                .iter()
                .map(|(seq, text)| {
                    let w: Vec<&str> = text.split_whitespace().collect();
                    json!({"seqno": seq, "permitdeny": w[0], "proto_str": w[1], "text": text})
                })
                .collect();
            json!({
                "op_ip_ipv6_mac": "ip",
                "show_ip_ipv6_mac": a.name,
                "TABLE_seqno": {"ROW_seqno": entries},
            })
        })
        .collect();
    pretty(&json!({"TABLE_ip_ipv6_mac": {"ROW_ip_ipv6_mac": rows}}))
}

fn trunks(dev: &Dev) -> String {
    let rows: Vec<Value> = dev
        .ifaces
        .iter()
        .filter_map(|i| match &i.mode {
            Mode::PortChannel(v) => Some(json!({"interface": i.name, "native": "1", "status": "trunking", "allowedvlans": vlan_list(v)})),
            _ => None,
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    pretty(&json!({"TABLE_interface": {"ROW_interface": rows}}))
}

fn vpc(e: &Estate, d: usize) -> Option<String> {
    let dev = &e.devs[d];
    let domain = dev.vpc_domain?;
    let peer = dev.vpc_peer?;
    let po = dev
        .ifaces
        .iter()
        .find(|i| i.peer_link)
        .expect("a peer link");
    let Mode::PortChannel(v) = &po.mode else {
        unreachable!("the peer link is a port channel")
    };
    Some(pretty(&json!({
        "vpc-domain-id": domain.to_string(),
        "vpc-peer-status": "peer-ok",
        "vpc-peer-status-reason": "SUCCESS",
        "vpc-peer-keepalive-status": "peer-alive",
        "vpc-peer-consistency": "consistent",
        "vpc-role": if peer > d { "primary" } else { "secondary" },
        "num-of-vpcs": "0",
        "TABLE_peerlink": {"ROW_peerlink": [{
            "peer-link-id": "1",
            "peerlink-ifindex": short(&po.name),
            "peer-link-port-state": "1",
            "peer-up-vlan-bitset": vlan_list(v),
        }]},
    })))
}

fn stp(dev: &Dev) -> String {
    let trees: Vec<Value> = dev
        .vlans
        .iter()
        .map(|v| {
            let ports: Vec<Value> = dev
                .ifaces
                .iter()
                .filter(|i| match &i.mode {
                    Mode::Access(a) => *a == v.id,
                    Mode::PortChannel(l) => l.contains(&v.id),
                    _ => false,
                })
                .map(|i| json!({"if_index": short(&i.name), "port_state": "forwarding", "port_role": "designated"}))
                .collect();
            json!({
                "tree_id": v.id.to_string(),
                "tree_tree_type": "rstp",
                "TABLE_port": {"ROW_port": ports},
            })
        })
        .collect();
    pretty(&json!({"TABLE_tree": {"ROW_tree": trees}}))
}

fn nve_peers(dev: &Dev) -> String {
    let rows: Vec<Value> = dev
        .nve_peers
        .iter()
        .map(|p| json!({"if-name": "nve1", "peer-ip": p.to_string(), "peer-state": "Up", "learn-type": "CP", "uptime": "5w6d", "router-mac": "n/a"}))
        .collect();
    pretty(&json!({"TABLE_nve_peers": {"ROW_nve_peers": rows}}))
}

fn nve_vnis(dev: &Dev) -> String {
    let l3 = dev.l3vni.as_ref();
    let rows: Vec<Value> = dev
        .vlans
        .iter()
        .filter_map(|v| {
            let vni = v.vni?;
            Some(if Some(vni) == l3.map(|x| x.1) {
                json!({"if-name": "nve1", "vni": vni.to_string(), "mcast": "n/a", "vni-state": "Up", "mode": "CP", "type": format!("L3 [{}]", l3.expect("the L3 VNI").0), "flags": ""})
            } else {
                json!({"if-name": "nve1", "vni": vni.to_string(), "mcast": "UnicastBGP", "vni-state": "Up", "mode": "CP", "type": format!("L2 [{}]", v.id), "flags": ""})
            })
        })
        .collect();
    pretty(&json!({"TABLE_nve_vni": {"ROW_nve_vni": rows}}))
}

fn evpn(e: &Estate, d: usize, with_ip: bool) -> String {
    let rows: Vec<Value> = e
        .hosts
        .iter()
        .filter(|h| h.dev == d)
        .map(|h| {
            let mut r = json!({
                "topo-id": h.vlan.to_string(),
                "mac-addr": dotted(h.mac),
                "prod-type": "Local",
                "flags": "L,",
                "seq-num": "0",
                "next-hop1": short(&h.port),
            });
            if with_ip {
                r["host-ip"] = json!(h.ip.to_string());
            }
            r
        })
        .collect();
    let t = if with_ip {
        "l2route_evpn_mac_ip_all"
    } else {
        "l2route_evpn_mac_all"
    };
    pretty(&json!({format!("TABLE_{t}"): {format!("ROW_{t}"): rows}}))
}

fn bgp_sessions(dev: &Dev) -> Option<String> {
    let bgp = dev.bgp.as_ref()?;
    let mut by_vrf: BTreeMap<&str, Vec<&Neighbor>> = BTreeMap::new();
    for n in &bgp.neighbors {
        by_vrf.entry(n.vrf.as_str()).or_default().push(n);
    }
    let total = bgp.neighbors.len();
    let up = bgp.neighbors.iter().filter(|n| n.up).count();
    let vrfs: Vec<Value> = by_vrf
        .iter()
        .map(|(vrf, ns)| {
            let rows: Vec<Value> = ns
                .iter()
                .map(|n| {
                    json!({
                        "neighbor-id": n.addr.to_string(),
                        "connectionsdropped": "0",
                        "remoteas": n.remote_as.to_string(),
                        "lastflap": "P41DT3H",
                        "lastread": "PT14S",
                        "lastwrite": "PT21S",
                        "state": if n.up { "Established" } else { "Idle" },
                        "localport": "179",
                        "remoteport": "41022",
                        "notificationssent": "0",
                        "notificationsreceived": "0",
                    })
                })
                .collect();
            json!({
                "vrf-name-out": vrf,
                "local-as": bgp.asn.to_string(),
                "vrfpeers": ns.len().to_string(),
                "vrfestablishedpeers": ns.iter().filter(|n| n.up).count().to_string(),
                "router-id": bgp.router_id.to_string(),
                "TABLE_neighbor": {"ROW_neighbor": rows},
            })
        })
        .collect();
    Some(pretty(&json!({
        "totalpeers": total.to_string(),
        "totalestablishedpeers": up.to_string(),
        "localas": bgp.asn.to_string(),
        "TABLE_vrf": {"ROW_vrf": vrfs},
    })))
}

/// The reply of each section of a switch, by section name.
pub fn render(e: &Estate, t: &Tables, d: usize) -> BTreeMap<&'static str, String> {
    let dev = &e.devs[d];
    let leaf = dev.l3vni.is_some();
    let feature = |on: bool, f: &dyn Fn() -> String| if on { f() } else { NO_FEATURE.to_string() };
    let mut out = BTreeMap::new();
    out.insert("config", config(e, d));
    out.insert("version", version(dev));
    out.insert("interfaces", interfaces(dev));
    out.insert("lldp", lldp(e, d));
    out.insert("cdp", NO_CDP.to_string());
    out.insert("vlans", vlans(dev));
    out.insert("vrfs", vrfs(dev));
    out.insert("rib", rib(dev, &t.ribs[d]));
    out.insert("mac_table", mac_table(t, d));
    out.insert("arp", arp(dev, t, d));
    out.insert("vrf_interfaces", vrf_interfaces(dev));
    out.insert("acl", acl(dev));
    out.insert("trunks", trunks(dev));
    out.insert("hsrp", NO_FEATURE.to_string());
    out.insert("vrrp", NO_FEATURE.to_string());
    out.insert("vpc", vpc(e, d).unwrap_or_else(|| NO_FEATURE.to_string()));
    out.insert("stp", stp(dev));
    out.insert("nve_peers", feature(leaf, &|| nve_peers(dev)));
    out.insert("nve_vnis", feature(leaf, &|| nve_vnis(dev)));
    out.insert("evpn_macs", feature(leaf, &|| evpn(e, d, false)));
    out.insert("evpn_mac_ips", feature(leaf, &|| evpn(e, d, true)));
    out.insert("mroutes", NO_FEATURE.to_string());
    out.insert("pim_neighbors", NO_FEATURE.to_string());
    out.insert(
        "bgp_sessions",
        bgp_sessions(dev).unwrap_or_else(|| NO_FEATURE.to_string()),
    );
    super::ospf::nxos(e, d, &t.redistributed, &mut out);
    out
}
