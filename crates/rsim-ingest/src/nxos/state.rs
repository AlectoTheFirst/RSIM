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
    row.get(key).and_then(Value::as_str).map(str::trim)
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
    if let Some((v, _)) = json("lldp") {
        st.neighbours_collected = true;
        for r in rows(&v, "nbor_detail") {
            if let Some(p) = text(r, "l_port_id") {
                st.neighbour_ports.insert(names.resolve(p));
            }
        }
    }
    if let Some((v, _)) = json("cdp") {
        st.neighbours_collected = true;
        for r in rows(&v, "cdp_neighbor_brief_info") {
            if let Some(p) = text(r, "intf_id") {
                st.neighbour_ports.insert(names.resolve(p));
            }
        }
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
    fn a_mac_of_each_form_is_read() {
        let m = mac("0000.5e00.5301").unwrap();
        assert_eq!(Some(m), mac("00:00:5e:00:53:01"));
        assert_eq!(Some(m), mac("00-00-5E-00-53-01"));
        assert_eq!(mac("0000.5e00.530"), None);
        assert_eq!(mac("0000.5e00.53zz"), None);
    }
}
