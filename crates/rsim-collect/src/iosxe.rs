//! The IOS XE source: read-only `show` commands over SSH, each answer as
//! text. `show ip arp` gives the ARP table of the global routing table, and
//! the section `arp_vrfs` holds the ARP table of each VRF of
//! `show vrf detail`.

use std::collections::BTreeSet;
use std::sync::Arc;

use rsim_store::{Class, Format};

use crate::cli::CliRules;
use crate::{
    BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Timeouts, TransportError, Vendor,
    fetch_sections,
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

/// The sections of an IOS XE router. A text answer keeps its raw bytes;
/// the change hash leaves out the volatile parts. The commands of the
/// section [`ARP_VRFS`] come from the answer of `show vrf detail`.
pub fn sections() -> Vec<SectionSpec> {
    SPECS
        .iter()
        .map(|(name, command, class, optional, volatile)| SectionSpec {
            name,
            command: (*command).to_string(),
            class: *class,
            format: Format::Text,
            volatile,
            extracts: &[],
            keep: &[],
            optional: *optional,
        })
        .collect()
}

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

    fn sections(&self, _device: &Device) -> Vec<SectionSpec> {
        sections()
    }

    /// Reads the sections of the static list, then the ARP table of each
    /// VRF of the answer of `show vrf detail` in name order. A failed or
    /// absent answer of the VRFs makes the section [`ARP_VRFS`] absent,
    /// except a connect error or a timeout, which the section takes as its
    /// error, as it does when each command of the VRFs ends in one.
    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let serial = self.ssh.serial(device);
            let banner_each = self.ssh.banner_each_command(device);
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            let (fixed, arp_vrfs): (Vec<SectionSpec>, Vec<SectionSpec>) = self
                .sections(device)
                .into_iter()
                .partition(|s| s.name != ARP_VRFS);
            let mut out = fetch_sections(fixed, timeouts, serial, read).await;
            let Some(spec) = arp_vrfs.into_iter().next() else {
                RULES.apply(&mut out, banner_each);
                return out;
            };
            let names = out
                .iter()
                .find(|s| s.spec.name == VRFS)
                .ok_or_else(|| {
                    TransportError::NotFound("the section of the VRFs is not read".into())
                })
                .and_then(vrf_names);
            let per_vrf = match &names {
                Ok(names) => {
                    let specs = names
                        .iter()
                        .map(|n| SectionSpec {
                            command: arp_vrf_command(n),
                            ..spec.clone()
                        })
                        .collect();
                    fetch_sections(specs, timeouts, serial, read).await
                }
                Err(_) => Vec::new(),
            };
            // The rules see each answer on its own, so that a rejection
            // fails one VRF and the banner is the head of all answers.
            let fixed_len = out.len();
            out.extend(per_vrf);
            RULES.apply(&mut out, banner_each);
            let answers = out.split_off(fixed_len);
            // A device that cannot be reached gives the error of the
            // connection, so the section keeps its last blob; another
            // failure of the VRFs makes the section absent.
            let unreachable = |e: &TransportError| {
                matches!(e, TransportError::Connect(_) | TransportError::Timeout)
            };
            let result = match names {
                Err(e) if unreachable(&e) => Err(e),
                Err(e) => Err(TransportError::NotFound(format!(
                    "the section of the VRFs failed: {e}"
                ))),
                Ok(names) => match answers.first().map(|a| &a.result) {
                    Some(Err(e))
                        if answers
                            .iter()
                            .all(|a| a.result.as_ref().is_err_and(unreachable)) =>
                    {
                        Err(e.clone())
                    }
                    _ => Ok(combine(&names, &answers)),
                },
            };
            out.push(RawSection { spec, result });
            out
        })
    }
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

/// The ARP tables of the VRFs as one text: for each VRF, a line
/// `VRF: <name>` and its answer, or the line `VRF: <name> failed`.
fn combine(names: &BTreeSet<String>, answers: &[RawSection]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, a) in names.iter().zip(answers) {
        match &a.result {
            Ok(bytes) => {
                out.extend_from_slice(format!("VRF: {name}\n").as_bytes());
                out.extend_from_slice(bytes);
                if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                    out.push(b'\n');
                }
            }
            Err(_) => out.extend_from_slice(format!("VRF: {name} failed\n").as_bytes()),
        }
    }
    out
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
