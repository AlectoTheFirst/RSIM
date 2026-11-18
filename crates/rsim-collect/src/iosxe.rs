//! The IOS XE source: read-only `show` commands over SSH, each answer as
//! text. `show ip arp` gives the ARP table of the global routing table, and
//! the section `arp_vrfs` holds the ARP table of each VRF of
//! `show vrf detail`.
//!
//! The BGP sections follow the setting of the device, [`CaptureBgp`]: the
//! session summary of the global table and of each VRF of the `router bgp`
//! block, and with `all` the neighbour detail and the tables of each IPv4
//! neighbour. The BGP commands are the commands of the HST collector, which
//! has not run against a live IOS XE router; they are not confirmed on a
//! device.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rsim_store::{Class, Format};

use crate::bgp::{self, CaptureBgp, Part, Plan};
use crate::cli::CliRules;
use crate::{
    BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Timeouts, TransportError, Vendor,
};

/// The CLI rules of IOS XE: the Cisco rules.
pub const RULES: CliRules = CliRules::CISCO;

/// The setup commands of a shell on IOS XE.
pub const SHELL_SETUP: [&str; 2] = ["terminal length 0", "terminal width 512"];

/// The ages of a route or a timer: `00:01:23`, `1d02h`, `3w2d` and `1y2w`.
const AGE_WORDS: [&str; 5] = ["~#:#:#", "~#d#h", "~#w#d", "~#y#w", "~#h#m"];

const CONFIG: &[&str] = &[
    "Building configuration",
    "Current configuration",
    "! Last configuration change",
    "! NVRAM config last updated",
    "! No configuration change since last restart",
];
/// The uptimes of the device, of its control processor and of each stack
/// member, and the times of the last reload.
const VERSION: &[&str] = &[
    "=*uptime is",
    "Uptime for this control processor",
    "Switch uptime",
    "System returned to ROM",
    "System restarted at",
    "Last reload",
];
/// The counters, the rates, the load and reliability, and the times of the
/// last packets.
const INTERFACES: &[&str] = &[
    "=# ",
    "reliability ",
    "Received ",
    "Output ",
    "Last input",
    "Last clearing",
    "Input queue",
    "Output queue",
    "Queueing strategy",
];
const LLDP: &[&str] = &["Time remaining"];
const CDP: &[&str] = &["Holdtime"];
const ROUTES: &[&str] = &AGE_WORDS;
/// The age of an ARP entry is a number of minutes.
const ARP: &[&str] = &["~#"];
/// The match counters of the access list entries.
const ACLS: &[&str] = &["~(#", "~match)", "~matches)"];
/// The counters and the times of the topology changes, the transitions and
/// the BPDUs.
const SPANNING_TREE: &[&str] = &[
    "Number of topology changes",
    "Number of transitions",
    "from ",
    "Times:",
    "Timers:",
    "BPDU:",
];
/// The hello timer, the state changes and the time left of each timer, a
/// number of seconds with a fraction such as `9.808`.
const HSRP: &[&str] = &["Next hello sent in", "=# state change", "~#.#"];
/// The time in the state and the time left of each timer.
const VRRP: &[&str] = &["State duration", "~#.#"];
const NONE: &[&str] = &[];

/// The section of the ARP tables of the VRFs. Each answer follows a line
/// `VRF: <name>`, and a VRF whose command fails has the line
/// `VRF: <name> failed`.
pub const ARP_VRFS: &str = "arp_vrfs";

/// The section whose answer names the VRFs.
const VRFS: &str = "vrfs";

/// The command of the ARP table of a VRF.
pub fn arp_vrf_command(vrf: &str) -> String {
    format!("show ip arp vrf {vrf}")
}

/// One section of the static list: the name, the command, the class,
/// whether a device can refuse it and the volatile parts.
type Spec = (
    &'static str,
    &'static str,
    Class,
    bool,
    &'static [&'static str],
);

const SPECS: &[Spec] = {
    use Class::{Configuration, Observation};
    &[
        (
            "config",
            "show running-config",
            Configuration,
            false,
            CONFIG,
        ),
        ("version", "show version", Configuration, false, VERSION),
        (
            "interfaces",
            "show interfaces",
            Observation,
            false,
            INTERFACES,
        ),
        (
            "lldp",
            "show lldp neighbors detail",
            Observation,
            true,
            LLDP,
        ),
        ("cdp", "show cdp neighbors detail", Observation, true, CDP),
        (VRFS, "show vrf detail", Configuration, true, NONE),
        ("rib", "show ip route vrf *", Observation, false, ROUTES),
        ("rib_global", "show ip route", Observation, false, ROUTES),
        ("arp", "show ip arp", Observation, true, ARP),
        ("acls", "show ip access-lists", Configuration, true, ACLS),
        ("inventory", "show inventory", Configuration, true, NONE),
        ("hsrp", "show standby brief", Observation, true, NONE),
        ("vrrp", "show vrrp brief", Observation, true, NONE),
        (
            "mac_table",
            "show mac address-table",
            Observation,
            true,
            NONE,
        ),
        (
            "spanning_tree",
            "show spanning-tree",
            Observation,
            true,
            SPANNING_TREE,
        ),
        ("vlans", "show vlan brief", Configuration, true, NONE),
        ("hsrp_detail", "show standby", Observation, true, HSRP),
        ("vrrp_detail", "show vrrp", Observation, true, VRRP),
        (ARP_VRFS, "show ip arp vrf <name>", Observation, true, ARP),
    ]
};

/// The sections of an IOS XE router with the BGP sections of the default
/// setting. A text answer keeps its raw bytes; the change hash leaves out
/// the volatile parts. The commands of the section [`ARP_VRFS`] come from
/// the answer of `show vrf detail`.
pub fn sections() -> Vec<SectionSpec> {
    sections_with(CaptureBgp::default())
}

fn text(
    name: &'static str,
    command: &str,
    class: Class,
    optional: bool,
    volatile: &'static [&'static str],
) -> SectionSpec {
    SectionSpec {
        name,
        command: command.to_string(),
        class,
        format: Format::Text,
        volatile,
        extracts: &[],
        keep: &[],
        optional,
    }
}

/// The section of the session summary of each VRF of the BGP process. Each
/// answer follows a line `VRF: <name>`, and a VRF whose command fails has
/// the line `VRF: <name> failed`.
pub const BGP_VRF_SESSIONS: &str = "bgp_vrf_sessions";

/// The command of the session summary of the global table.
pub const BGP_SESSIONS_COMMAND: &str = "show ip bgp summary";

/// The command of the session summary of a VRF.
pub fn bgp_vrf_sessions_command(vrf: &str) -> String {
    format!("show ip bgp vpnv4 vrf {vrf} summary")
}

/// The command of a table of a neighbour, with the index of its direction
/// in [`bgp::DIRECTIONS`].
pub fn bgp_route_command(vrf: &str, peer: Ipv4Addr, direction: usize) -> String {
    let scope = if vrf == bgp::DEFAULT_VRF {
        String::new()
    } else {
        format!("vpnv4 vrf {vrf} ")
    };
    format!(
        "show ip bgp {scope}neighbors {peer} {}",
        bgp::DIRECTIONS[direction]
    )
}

/// The numbers and the ages of a session summary: the memory, the table
/// versions, the message counters, the queues, the prefix counts, the up
/// and down times and the time of the most networks. The change hash covers
/// the addresses and the state words; the AS of a neighbour and the local
/// AS are in the running config.
const BGP_COUNTERS: &[&str] = &[
    "=# networks peaked",
    "~#",
    "~#/#",
    "~#:#:#",
    "~#d#h",
    "~#w#d",
    "~#y#w",
    "~#h#m",
];
/// The numbers, the times and the ages of the neighbour detail, also in
/// parentheses, with a final `;` or in hexadecimal, such as the TCP
/// sequence numbers and the current time of the event timers.
const BGP_NEIGHBORS: &[&str] = &[
    "~#", "~#/#", "~#;", "~(#", "~#)", "~0x*", "~#:#:#", "~#d#h", "~#w#d", "~#y#w", "~#h#m",
];
/// The table version of a table of a neighbour.
const BGP_ROUTES: &[&str] = &["BGP table version"];

/// The sections of an IOS XE router with the BGP sections of a setting, in
/// the order of the fetch.
pub fn sections_with(capture: CaptureBgp) -> Vec<SectionSpec> {
    use Class::Observation;
    let mut out: Vec<SectionSpec> = SPECS
        .iter()
        .map(|(name, command, class, optional, volatile)| {
            text(name, command, *class, *optional, volatile)
        })
        .collect();
    if capture.sessions() {
        out.push(text(
            bgp::SESSIONS,
            BGP_SESSIONS_COMMAND,
            Observation,
            true,
            BGP_COUNTERS,
        ));
        out.push(text(
            BGP_VRF_SESSIONS,
            "show ip bgp vpnv4 vrf <name> summary",
            Observation,
            true,
            BGP_COUNTERS,
        ));
    }
    if capture.all() {
        out.push(text(
            bgp::NEIGHBORS,
            "show bgp all neighbors",
            Observation,
            true,
            BGP_NEIGHBORS,
        ));
        out.push(text(
            bgp::ROUTES,
            "show ip bgp [vpnv4 vrf <vrf>] neighbors <address> <direction>",
            Observation,
            true,
            BGP_ROUTES,
        ));
    }
    out.sort_by_key(|s| DERIVED.contains(&s.name));
    out
}

/// The sections whose commands come from the answers of other sections.
const DERIVED: [&str; 3] = [ARP_VRFS, BGP_VRF_SESSIONS, bgp::ROUTES];

/// Reads an IOS XE router.
pub struct IosxeSource {
    ssh: Arc<dyn Ssh>,
}

impl IosxeSource {
    pub fn new(ssh: Arc<dyn Ssh>) -> IosxeSource {
        IosxeSource { ssh }
    }
}

impl Source for IosxeSource {
    fn vendor(&self) -> Vendor {
        Vendor::Iosxe
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections_with(device.capture_bgp)
    }

    /// Reads the sections of the static list, then the sections whose
    /// commands come from the answers before them: the ARP table of each
    /// VRF of the answer of `show vrf detail` in name order, the session
    /// summary of each VRF of the `router bgp` block of the running config
    /// in name order, and the 3 tables of each IPv4 neighbour of the
    /// session summaries. A failed or absent answer of the section that
    /// names the commands makes the section absent, except a connect error
    /// or a timeout, which the section takes as its error, as it does when
    /// each of its commands ends in one.
    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            bgp::fetch_text(
                self.sections(device),
                &DERIVED,
                &RULES,
                self.ssh.banner_each_command(device),
                timeouts,
                self.ssh.serial(device),
                read,
                |spec, view| match spec.name {
                    ARP_VRFS => Plan {
                        parts: view
                            .iter()
                            .find(|s| s.spec.name == VRFS)
                            .ok_or_else(|| {
                                TransportError::NotFound(
                                    "the section of the VRFs is not read".into(),
                                )
                            })
                            .and_then(vrf_names)
                            .map(|names| {
                                names
                                    .into_iter()
                                    .map(|n| Part {
                                        command: arp_vrf_command(&n),
                                        head: n,
                                    })
                                    .collect()
                            }),
                        what: "the section of the VRFs",
                        line: bgp::VRF_LINE,
                    },
                    BGP_VRF_SESSIONS => {
                        bgp::vrf_session_plan(view, bgp_vrfs, bgp_vrf_sessions_command)
                    }
                    _ => bgp::text_route_plan(view, BGP_VRF_SESSIONS, bgp_route_command),
                },
            )
            .await
        })
    }
}

/// The VRFs of the `router bgp` block: `address-family ipv4 vrf <name>`
/// and `address-family ipv4 unicast vrf <name>`.
fn bgp_vrfs(config: &str) -> Vec<String> {
    bgp::config_bgp_vrfs(config, |l| {
        let l = l.trim();
        l.strip_prefix("address-family ipv4 vrf ")
            .or_else(|| l.strip_prefix("address-family ipv4 unicast vrf "))
            .map(str::trim)
    })
}

/// The names of the VRFs in the answer of `show vrf detail`, in name order:
/// the word after `VRF` on each line `VRF <name> (VRF Id = <n>); ...`. A
/// failed answer gives its error.
fn vrf_names(vrfs: &RawSection) -> Result<BTreeSet<String>, TransportError> {
    let mut probe = [vrfs.clone()];
    RULES.apply(&mut probe, false);
    let bytes = probe[0].result.as_ref().map_err(Clone::clone)?;
    Ok(String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("VRF ")?;
            let (name, tail) = rest.split_once(' ')?;
            (tail.starts_with("(VRF Id") && name.bytes().all(|b| b.is_ascii_graphic()))
                .then(|| name.to_string())
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(text: &str) -> RawSection {
        RawSection {
            spec: sections().into_iter().find(|s| s.name == VRFS).unwrap(),
            result: Ok(text.as_bytes().to_vec()),
        }
    }

    #[test]
    fn the_vrf_names_come_from_the_header_lines_in_name_order() {
        let text = "VRF RED (VRF Id = 2); default RD 65000:2; default VPNID <not set>\n  Interfaces:\n    Gi2\nVRF BLUE (VRF Id = 1); default RD <not set>; default VPNID <not set>\n  Description: VRF RED\nVRF Mgmt-intf (VRF Id = 3); default RD <not set>; default VPNID <not set>\n";
        let names: Vec<String> = vrf_names(&section(text)).unwrap().into_iter().collect();
        assert_eq!(names, ["BLUE", "Mgmt-intf", "RED"]);
    }

    #[test]
    fn a_rejected_answer_of_the_vrfs_is_an_error() {
        let s = section("% Invalid input detected at '^' marker.\n");
        assert!(vrf_names(&s).is_err());
    }
}
