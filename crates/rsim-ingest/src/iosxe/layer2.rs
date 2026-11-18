//! The layer 2 part of a Catalyst switch in the form of the NX-OS layer 2
//! lowering: the switch ports, the VLANs, the SVIs with their gateway facts
//! and the interface state. The snapshot has no MAC table and no spanning
//! tree state of an IOS-XE device.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::config::Config;
use super::profile::{
    DEFAULT_VLAN, MODE_WITHOUT_LINE, UP_WITHOUT_SHUTDOWN, VTP_MODES_WITH_VLAN_LINES,
};
use super::state::State;
use crate::iosxr::lower::{Group, GroupState, Port};
use crate::nxos;
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

/// The VLANs of the device as ranges, with the default VLAN, and the VLANs
/// of a `vlan` stanza with a line that the lowering does not read.
pub(super) fn vlans(cfg: &Config) -> (Ranges, Ranges) {
    let mut all = vec![(DEFAULT_VLAN, DEFAULT_VLAN)];
    let mut unknown = Vec::new();
    for v in &cfg.vlans {
        all.extend(v.ranges.iter().copied());
        if !v.unhandled.is_empty() {
            unknown.extend(v.ranges.iter().copied());
        }
    }
    (all, unknown)
}

/// The interfaces in the form of the NX-OS layer 2 lowering. A port with an
/// address, with a sub-interface or with `no switchport` is a routed port. A
/// switch port with no `switchport mode` line, and each switch port of a
/// switch whose VLANs are not in the running config, gets an unhandled
/// line, so it gives `Unknown`.
pub(super) fn interfaces(cfg: &Config) -> Vec<nxos::config::Interface> {
    let vlans_unknown = match &cfg.vtp_mode {
        Some((m, _)) if VTP_MODES_WITH_VLAN_LINES.contains(&m.as_str()) => None,
        Some((m, _)) => Some(format!(
            "VTP mode {m}, so the VLANs are not in the running config"
        )),
        None => Some("no vtp mode line, so the VLANs are not in the running config".to_string()),
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
/// interface state and the ports with an LLDP or CDP neighbour. The MAC
/// table is not collected.
pub(super) fn switch_state(st: &State) -> nxos::state::State {
    let mut out = nxos::state::State {
        no_mac_table: true,
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
                            "{} group {}: the virtual MAC is not known",
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
