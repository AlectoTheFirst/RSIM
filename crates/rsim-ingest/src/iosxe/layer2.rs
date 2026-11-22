//! The layer 2 part of a Catalyst switch in the form of the NX-OS layer 2
//! lowering: the switch ports, the VLANs of the config or of
//! `show vlan brief`, the SVIs with their gateway facts, the interface
//! state, the MAC table and the spanning tree state of each port.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::config::Config;
use super::profile::{
    DEFAULT_VLAN, MODE_WITHOUT_LINE, UP_WITHOUT_SHUTDOWN, VLAN_ACTIVE, VLAN_UNSUPPORTED,
    VTP_MODES_WITH_VLAN_LINES,
};
use super::state::{State, StpState};
use crate::collected::Collected;
use crate::iosxr::lower::{Group, GroupState, Port};
use crate::nxos;
use crate::nxos::config::PortMode;
use crate::nxos::layer2::{Gateway, svi_vlan};

/// True if the device has a layer 2 part: a switch port, a `vlan` line or
/// an SVI.
pub(super) fn has_layer2(cfg: &Config) -> bool {
    !cfg.vlans.is_empty()
        || cfg
            .interfaces
            .iter()
            .any(|i| i.switchport == Some(true) || svi_vlan(&i.name).is_some())
}

/// VLAN ranges.
type Ranges = Vec<(u16, u16)>;

/// True if the running config holds the VLANs of the switch, by its VTP
/// mode.
fn vlans_in_config(cfg: &Config) -> bool {
    matches!(&cfg.vtp_mode, Some((m, _)) if VTP_MODES_WITH_VLAN_LINES.contains(&m.as_str()))
}

/// The VLANs of the device as ranges, with the default VLAN, and the VLANs
/// that make a port `Unknown`: the VLANs of a `vlan` stanza with a line
/// that the lowering does not read, the VLANs of a `vlan filter` line, and
/// on a switch whose VLANs are not in the running config, the VLANs of
/// `show vlan brief` with a status other than active. A reserved VLAN that
/// the switch does not support is not a VLAN of the switch.
pub(super) fn vlans(cfg: &Config, st: &State) -> (Ranges, Ranges) {
    let mut all = vec![(DEFAULT_VLAN, DEFAULT_VLAN)];
    let mut unknown = cfg.filtered_vlans.clone();
    for v in &cfg.vlans {
        all.extend(v.ranges.iter().copied());
        if !v.unhandled.is_empty() {
            unknown.extend(v.ranges.iter().copied());
        }
    }
    if !vlans_in_config(cfg)
        && let Some(Ok(rows)) = &st.vlans
    {
        for r in rows.iter().filter(|r| supported(r)) {
            all.push((r.vlan, r.vlan));
            if !r.status.eq_ignore_ascii_case(VLAN_ACTIVE) {
                unknown.push((r.vlan, r.vlan));
            }
        }
    }
    (all, unknown)
}

/// The VLANs of `show vlan brief` that are not active, on a switch whose
/// VLANs are not in the running config, each with its status.
pub(super) fn inactive_vlans(cfg: &Config, st: &State) -> Vec<(u16, String)> {
    match &st.vlans {
        Some(Ok(rows)) if !vlans_in_config(cfg) => rows
            .iter()
            .filter(|r| supported(r) && !r.status.eq_ignore_ascii_case(VLAN_ACTIVE))
            .map(|r| (r.vlan, r.status.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

/// False for a VLAN of `show vlan brief` with the status of a reserved
/// VLAN that the switch does not support.
fn supported(r: &super::state::VlanRow) -> bool {
    !r.status.eq_ignore_ascii_case(VLAN_UNSUPPORTED)
}

/// The interfaces in the form of the NX-OS layer 2 lowering. A port with an
/// address, with a sub-interface or with `no switchport` is a routed port. A
/// switch port with no `switchport mode` line gets an unhandled line, so it
/// gives `Unknown`. So does each switch port of a switch whose VLANs are not
/// in the running config, unless the section `vlans` gives them, and each
/// trunk of a switch with `vlan dot1q tag native`.
pub(super) fn interfaces(cfg: &Config, st: &State) -> Vec<nxos::config::Interface> {
    let not_in_config = match &cfg.vtp_mode {
        Some((m, _)) => format!("VTP mode {m}, VLANs not in the running config"),
        None => "no vtp mode line, VLANs not in the running config".to_string(),
    };
    let vlans_unknown = match &st.vlans {
        _ if vlans_in_config(cfg) => None,
        Some(Ok(_)) => None,
        Some(Err(e)) => Some(format!("{not_in_config}, show vlan brief not read: {e}")),
        None => Some(not_in_config),
    };
    cfg.interfaces
        .iter()
        .map(|i| {
            let has_sub = cfg.interfaces.iter().any(|x| {
                x.name
                    .strip_prefix(i.name.as_str())
                    .is_some_and(|r| r.starts_with('.'))
            });
            let routed = i.switchport == Some(false)
                || !i.addresses.is_empty()
                || i.dynamic_address.is_some()
                || has_sub;
            let switchport = if routed { Some(false) } else { i.switchport };
            let mut unhandled = i.unhandled.clone();
            if switchport == Some(true) && i.mode.is_none() {
                unhandled.push(MODE_WITHOUT_LINE.to_string());
            }
            if let (Some(true), Some(why)) = (switchport, &vlans_unknown) {
                unhandled.push(why.clone());
            }
            if let (Some(true), Some(PortMode::Trunk), Some(line)) =
                (switchport, i.mode, &cfg.native_tagging)
            {
                unhandled.push(line.clone());
            }
            nxos::config::Interface {
                name: i.name.clone(),
                admin_up: i.admin_up.or(UP_WITHOUT_SHUTDOWN.then_some(true)),
                vrf: i.vrf.as_ref().map(|v| v.0.clone()),
                addresses: i.addresses.clone(),
                acl_in: i.acl_in.clone(),
                acl_out: i.acl_out.clone(),
                nat: i.nat,
                qos_in: i.qos_in.clone(),
                qos_out: i.qos_out.clone(),
                switchport,
                mode: i.mode,
                access_vlan: i.access_vlan,
                native_vlan: i.native_vlan,
                allowed: i.allowed.clone(),
                channel_group: i.channel_group.map(|c| c.0),
                unhandled,
                lines: i.lines,
                ..nxos::config::Interface::default()
            }
        })
        .collect()
}

/// The collected state in the form of the NX-OS layer 2 lowering: the
/// interface state, the ports with an LLDP or CDP neighbour and the
/// spanning tree state of each port. With no MAC table that the template
/// reads, the MAC lookup gives `Unknown` for a MAC that the twin does not
/// place.
pub(super) fn switch_state(st: &State) -> nxos::state::State {
    let mut out = nxos::state::State {
        no_mac_table: !matches!(st.mac_table, Some(Ok(_))),
        stp: match &st.stp {
            Some(Ok(m)) => Some(
                m.iter()
                    .map(|(k, (s, span))| {
                        let fwd = match s {
                            StpState::Forwarding => Some(true),
                            StpState::NotForwarding => Some(false),
                            StpState::Unknown(_) => None,
                        };
                        (k.clone(), (fwd, span.clone()))
                    })
                    .collect(),
            ),
            _ => None,
        },
        ..nxos::state::State::default()
    };
    if let Some(Ok(m)) = &st.l3.interfaces {
        for (name, s) in m {
            out.interfaces.insert(
                name.clone(),
                nxos::state::IfState {
                    admin_up: Some(!s.admin_down),
                    oper_up: s.oper_up,
                    mode: None,
                    span: Some(s.span.clone()),
                },
            );
        }
    }
    for n in [&st.l3.lldp, &st.l3.cdp] {
        if let Some(Ok(rows)) = n {
            out.neighbours_collected = true;
            out.neighbour_ports
                .extend(rows.iter().map(|r| r.port.clone()));
        }
    }
    out
}

/// The collected tables in the form of the NX-OS layer 2 lowering: the rows
/// of the MAC table.
pub(super) fn collected(st: &State) -> Collected {
    Collected {
        macs: st.mac_table.iter().flatten().flatten().cloned().collect(),
        ..Collected::default()
    }
}

/// The gateway facts of each lowered layer 3 interface: its MAC in
/// `show interfaces`, and the virtual MAC and the virtual addresses of its
/// active groups. A group whose state or virtual MAC is not known makes the
/// hand-off of an SVI `Unknown`.
pub(super) fn gateways(active: &[Port], groups: &[Group], st: &State) -> BTreeMap<String, Gateway> {
    let states = st.l3.interfaces.as_ref().and_then(|x| x.as_ref().ok());
    active
        .iter()
        .map(|p| {
            let name = &p.i.name;
            let mut g = Gateway {
                svi_mac: states
                    .and_then(|m| m.get(name))
                    .and_then(|s| Some((s.mac?, s.span.clone()))),
                ..Gateway::default()
            };
            for x in groups.iter().filter(|x| &x.interface == name) {
                match (&x.state, x.vmac) {
                    (GroupState::Active, Some(m)) => {
                        for a in &x.addresses {
                            g.active.push((m, IpAddr::V4(*a), x.spans.clone()));
                        }
                        g.vmac.get_or_insert((m, x.spans.clone()));
                    }
                    (GroupState::NotActive, Some(m)) => {
                        g.vmac.get_or_insert((m, x.spans.clone()));
                    }
                    (GroupState::NotActive, None) => {}
                    (GroupState::Active, None) => {
                        g.unknown = Some(format!(
                            "{} group {}: virtual MAC not known",
                            x.what, x.group
                        ));
                    }
                    (GroupState::Unknown(why), _) => {
                        g.unknown = Some(format!("{} group {}: {why}", x.what, x.group));
                    }
                }
            }
            (name.clone(), g)
        })
        .collect()
}
