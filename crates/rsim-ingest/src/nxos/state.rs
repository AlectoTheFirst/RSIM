//! The collected JSON sections of an NX-OS switch that the lowering reads:
//! the state of the interfaces, the HSRP and VRRP groups, and the ports with
//! an LLDP or a CDP neighbour. Each ROW_x of a section is a list.

use std::collections::{BTreeMap, BTreeSet};

use rsim_core::{Mac, SourceSpan};
use serde_json::Value;

use super::config::FhrpKind;
use super::names::Names;

/// The state of an interface from the kept fields of `show interface`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfState {
    pub admin_up: Option<bool>,
    pub oper_up: Option<bool>,
    /// The kept field `eth_mode`, for example `access`, `trunk` or
    /// `routed`, in lower case.
    pub mode: Option<String>,
    pub span: Option<SourceSpan>,
}

/// The state of an HSRP or a VRRP group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupState {
    pub kind: FhrpKind,
    pub interface: String,
    pub group: u32,
    pub state: Option<String>,
    pub vip: Option<String>,
    pub vmac: Option<Mac>,
    pub span: SourceSpan,
}

pub use crate::links::Neighbour;

/// The name of a neighbour: the text without a serial number in
/// parentheses (CDP of NX-OS) and without the domain, in lower case.
pub fn neighbour_name(s: &str) -> Option<String> {
    let s = s.trim();
    let s = match s.find('(') {
        Some(i) if s.ends_with(')') => s[..i].trim(),
        _ => s,
    };
    let s = s.split('.').next().unwrap_or(s).trim();
    (!s.is_empty() && s != "null").then(|| s.to_ascii_lowercase())
}

/// A peer tunnel end of `show nve peers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvePeer {
    pub address: std::net::IpAddr,
    /// `None` if the state word is not `Up` or `Down`.
    pub up: Option<bool>,
    pub span: SourceSpan,
}

/// A VNI of `show nve vni`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NveVni {
    pub vni: u32,
    /// `None` if the state word is not `Up` or `Down`.
    pub up: Option<bool>,
    pub span: SourceSpan,
}

/// The collected sections of a switch.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub interfaces: BTreeMap<String, IfState>,
    pub groups: Vec<GroupState>,
    /// True if the HSRP or VRRP section is in the snapshot.
    pub hsrp_collected: bool,
    pub vrrp_collected: bool,
    /// The ports with an LLDP or a CDP neighbour.
    pub neighbour_ports: BTreeSet<String>,
    /// True if the LLDP or the CDP section is in the snapshot.
    pub neighbours_collected: bool,
    /// The LLDP and CDP rows.
    pub neighbours: Vec<Neighbour>,
    /// The kept field `host_name` of the version section, as a neighbour
    /// name.
    pub host_name: Option<String>,
    /// The state of the vPC domain, if the section is in the snapshot.
    pub vpc: Option<VpcState>,
    /// The peer tunnel ends, if the section was collected. An error names a
    /// row that is not read.
    pub nve_peers: Option<Result<Vec<NvePeer>, String>>,
    /// The VNIs of the NVE interface, if the section was collected. An error
    /// names a row that is not read.
    pub nve_vnis: Option<Result<Vec<NveVni>, String>>,
    /// The VNI of each route path with a VXLAN encapsulation, by VRF,
    /// prefix and next hop, from the route table section.
    pub vxlan_paths: BTreeMap<(String, String, String), (u32, SourceSpan)>,
}

/// The state of a vPC domain from `show vpc`, with the fields that HST
/// reads. HST marks these names as not confirmed on a device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VpcState {
    pub domain: Option<u32>,
    /// True for the peer status `peer-ok`.
    pub peer_ok: Option<bool>,
    pub peer_link: Option<String>,
    pub span: Option<SourceSpan>,
}

/// A MAC in the form of NX-OS, `0000.5e00.5301`, or with `:` or `-`.
pub fn mac(s: &str) -> Option<Mac> {
    let hex: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 12
        || s.chars()
            .any(|c| !c.is_ascii_hexdigit() && !".:-".contains(c))
    {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(Mac(out))
}

/// The rows of `TABLE_<t>/ROW_<t>` at the top of a section.
fn rows<'a>(v: &'a Value, t: &str) -> &'a [Value] {
    v.get(format!("TABLE_{t}"))
        .and_then(|x| x.get(format!("ROW_{t}")))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn text<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "null")
}

fn up(s: Option<&str>) -> Option<bool> {
    match s?.to_ascii_lowercase().as_str() {
        "up" => Some(true),
        "down" => Some(false),
        _ => None,
    }
}

/// Reads the sections. `sections` maps a section name to its bytes and its
/// file name. A section that is not JSON reads as absent.
pub fn read(sections: &BTreeMap<String, (Vec<u8>, String)>, names: &Names) -> State {
    let mut st = State::default();
    let json = |n: &str| -> Option<(Value, &str)> {
        let (b, f) = sections.get(n)?;
        Some((serde_json::from_slice(b).ok()?, f.as_str()))
    };
    let line =
        |file: &str, i: usize| SourceSpan::line(file, u32::try_from(i + 1).unwrap_or(u32::MAX));
    if let Some((v, file)) = json("interfaces") {
        for (i, r) in rows(&v, "interface").iter().enumerate() {
            let Some(name) = text(r, "interface") else {
                continue;
            };
            // The first of these fields that the row has decides, as in the
            // HST parser.
            let admin = ["admin_state", "svi_admin_state", "state", "svi_line_proto"]
                .iter()
                .find_map(|k| text(r, k))
                .map(|v| v == "up");
            let oper = up(text(r, "state")).or_else(|| up(text(r, "svi_line_proto")));
            st.interfaces.insert(
                names.resolve(name),
                IfState {
                    admin_up: admin,
                    oper_up: oper,
                    mode: text(r, "eth_mode").map(str::to_ascii_lowercase),
                    span: Some(line(file, i)),
                },
            );
        }
    }
    for (kind, section, table, ifk, groupk, vipk) in [
        (
            FhrpKind::Hsrp,
            "hsrp",
            "grp_detail",
            "sh_if_index",
            "sh_group_num",
            "sh_vip",
        ),
        (
            FhrpKind::Vrrp,
            "vrrp",
            "vrrp_group",
            "sh_if_name",
            "sh_group_id",
            "sh_vip_addr",
        ),
    ] {
        let Some((v, file)) = json(section) else {
            continue;
        };
        match kind {
            FhrpKind::Hsrp => st.hsrp_collected = true,
            FhrpKind::Vrrp => st.vrrp_collected = true,
        }
        for (i, r) in rows(&v, table).iter().enumerate() {
            let Some(iface) = text(r, ifk) else {
                continue;
            };
            let group = r
                .get(groupk)
                .and_then(|g| g.as_u64().or_else(|| g.as_str()?.trim().parse().ok()))
                .and_then(|g| u32::try_from(g).ok());
            let Some(group) = group else {
                continue;
            };
            st.groups.push(GroupState {
                kind,
                interface: names.resolve(iface),
                group,
                state: text(r, "sh_group_state").map(str::to_string),
                vip: text(r, vipk).map(str::to_string),
                vmac: text(r, "sh_vmac").and_then(mac),
                span: line(file, i),
            });
        }
    }
    for (section, table, local, name, chassis) in [
        (
            "lldp",
            "nbor_detail",
            "l_port_id",
            "sys_name",
            Some("chassis_id"),
        ),
        (
            "cdp",
            "cdp_neighbor_brief_info",
            "intf_id",
            "device_id",
            None,
        ),
    ] {
        let Some((v, file)) = json(section) else {
            continue;
        };
        st.neighbours_collected = true;
        for (i, r) in rows(&v, table).iter().enumerate() {
            let Some(p) = text(r, local) else {
                continue;
            };
            let port = names.resolve(p);
            st.neighbour_ports.insert(port.clone());
            let remote_port = text(r, "port_id").map(str::to_string);
            st.neighbours.push(Neighbour {
                port,
                name: text(r, name).and_then(neighbour_name),
                port_mac: remote_port.as_deref().and_then(mac),
                remote_port,
                chassis: chassis.and_then(|k| text(r, k)).and_then(mac),
                span: line(file, i),
            });
        }
    }
    if let Some((v, file)) = json("vpc") {
        st.vpc = Some(VpcState {
            domain: v
                .get("vpc-domain-id")
                .and_then(|d| d.as_u64().or_else(|| d.as_str()?.trim().parse().ok()))
                .and_then(|d| u32::try_from(d).ok()),
            peer_ok: text(&v, "vpc-peer-status")
                .map(|t| t.eq_ignore_ascii_case(super::profile::STATE_WORDS[0])),
            peer_link: rows(&v, "peerlink")
                .first()
                .and_then(|r| text(r, "peerlink-ifindex"))
                .map(|p| names.resolve(p)),
            span: Some(line(file, 0)),
        });
    }
    // The keys of the NVE sections are not confirmed on a device. A row
    // with no address or VNI makes the section unread.
    if let Some((v, file)) = json("nve_peers") {
        let peers =
            rows(&v, "nve_peers")
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    Ok(NvePeer {
                        address: text(r, "peer-ip").and_then(|a| a.parse().ok()).ok_or_else(
                            || format!("row {} of the NVE peers has no peer address", i + 1),
                        )?,
                        up: up(text(r, "peer-state")),
                        span: line(file, i),
                    })
                })
                .collect();
        st.nve_peers = Some(peers);
    }
    if let Some((v, file)) = json("nve_vnis") {
        let vnis = rows(&v, "nve_vni")
            .iter()
            .enumerate()
            .map(|(i, r)| {
                Ok(NveVni {
                    vni: text(r, "vni")
                        .and_then(|a| a.parse().ok())
                        .ok_or_else(|| format!("row {} of the NVE VNIs has no VNI", i + 1))?,
                    up: up(text(r, "vni-state")),
                    span: line(file, i),
                })
            })
            .collect();
        st.nve_vnis = Some(vnis);
    }
    // The keys `segid` and `encap` are not confirmed on a device.
    if let Some((v, file)) = json("rib") {
        let mut i = 0usize;
        for vrf in rows(&v, "vrf") {
            let Some(name) = text(vrf, "vrf-name-out") else {
                continue;
            };
            for af in rows(vrf, "addrf") {
                for p in rows(af, "prefix") {
                    let Some(prefix) = text(p, "ipprefix") else {
                        continue;
                    };
                    for path in rows(p, "path") {
                        i += 1;
                        let vxlan =
                            text(path, "encap").is_some_and(|e| e.eq_ignore_ascii_case("vxlan"));
                        let segid = path
                            .get("segid")
                            .and_then(|g| g.as_u64().or_else(|| g.as_str()?.trim().parse().ok()))
                            .and_then(|g| u32::try_from(g).ok());
                        let (Some(nh), Some(segid), true) = (text(path, "ipnexthop"), segid, vxlan)
                        else {
                            continue;
                        };
                        st.vxlan_paths.insert(
                            (name.to_string(), prefix.to_string(), nh.to_string()),
                            (segid, line(file, i - 1)),
                        );
                    }
                }
            }
        }
    }
    if let Some((v, _)) = json("version") {
        st.host_name = text(&v, "host_name").and_then(neighbour_name);
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_collector_fixture_gives_the_admin_state() {
        let bytes = include_bytes!("../../../rsim-collect/tests/fixtures/nxos/interface.json");
        let sections = BTreeMap::from([(
            "interfaces".to_string(),
            (bytes.to_vec(), "s1/interfaces".to_string()),
        )]);
        let names = Names::new(["Ethernet1/1", "Ethernet1/2", "Vlan10"]);
        let st = read(&sections, &names);
        for n in ["Ethernet1/1", "Ethernet1/2", "Vlan10"] {
            assert_eq!(st.interfaces[n].admin_up, Some(true), "{n}");
            assert_eq!(st.interfaces[n].oper_up, Some(true), "{n}");
        }
    }

    #[test]
    fn a_neighbour_name_has_no_domain_and_no_serial() {
        assert_eq!(
            neighbour_name("leaf2.example.test(FDO1234)"),
            Some("leaf2".into())
        );
        assert_eq!(neighbour_name("Leaf2"), Some("leaf2".into()));
        assert_eq!(neighbour_name("null"), None);
    }

    #[test]
    fn a_mac_of_each_form_is_read() {
        let m = mac("0000.5e00.5301").unwrap();
        assert_eq!(Some(m), mac("00:00:5e:00:53:01"));
        assert_eq!(Some(m), mac("00-00-5E-00-53-01"));
        assert_eq!(mac("0000.5e00.530"), None);
        assert_eq!(mac("0000.5e00.53zz"), None);
    }
}
