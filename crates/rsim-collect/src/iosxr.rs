//! The IOS XR source: read-only `show` commands over SSH, each answer as
//! text. The commands are the commands of the HST collector, which has not
//! run against a live IOS XR router; they are not confirmed on a device.
//!
//! The BGP sections follow the setting of the device, [`CaptureBgp`]: the
//! session summary of the global table and of each VRF of the `router bgp`
//! block, which cover IPv4 unicast, and with `all` the neighbour detail
//! and the tables of each IPv4 neighbour.

use std::net::Ipv4Addr;
use std::sync::Arc;

use rsim_store::{Class, Format};

use crate::bgp::{self, BgpCaptures, CaptureBgp};
use crate::cli::CliRules;
use crate::{BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Timeouts, Vendor};

/// The CLI rules of IOS XR: the Cisco rules.
pub const RULES: CliRules = CliRules::CISCO;

/// The setup commands of a shell on IOS XR.
pub const SHELL_SETUP: [&str; 2] = ["terminal length 0", "terminal width 512"];

/// IOS XR prints the time of the command before each answer, for example
/// `Tue Nov 17 20:52:43.123 UTC`. Each list of volatile parts starts with
/// these line starts.
macro_rules! volatile {
    ($($p:expr),* $(,)?) => {
        &["Mon ", "Tue ", "Wed ", "Thu ", "Fri ", "Sat ", "Sun ", $($p),*]
    };
}

/// The ages of a route, an ARP entry or a timer: `00:01:23`, `1d02h`,
/// `3w2d` and `1y2w`.
macro_rules! ages {
    ($($p:expr),* $(,)?) => {
        volatile!["~#:#:#", "~#d#h", "~#w#d", "~#y#w", "~#h#m", $($p),*]
    };
}

const CONFIG: &[&str] = volatile![
    "Building configuration",
    "!! IOS XR Configuration",
    "!! Last configuration change",
];
const VERSION: &[&str] = volatile!["=*uptime is", "System uptime"];
/// The counters, the rates, the load and reliability and the times of the
/// last packets.
const INTERFACES: &[&str] = volatile![
    "=# ",
    "reliability ",
    "Reliability ",
    "Received ",
    "Output ",
    "Last link flapped",
    "Last input",
    "Last clearing",
];
const LLDP: &[&str] = volatile!["Time remaining", "Age:"];
const CDP: &[&str] = volatile!["Holdtime"];
const AGES: &[&str] = ages![];
const HSRP: &[&str] = ages![
    "Next hello",
    "Last state change",
    "Last coup",
    "Last resign"
];
const TIME: &[&str] = volatile![];

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
        ("vrfs", "show vrf all detail", Configuration, false, TIME),
        ("rib", "show route vrf all ipv4", Observation, false, AGES),
        ("arp", "show arp vrf all", Observation, true, AGES),
        ("inventory", "show inventory", Configuration, true, TIME),
        ("hsrp", "show hsrp", Observation, true, HSRP),
    ]
};

/// The section of the session summary of each VRF of the BGP process. Each
/// answer follows a line `VRF: <name>`, and a VRF whose command fails has
/// the line `VRF: <name> failed`.
pub const BGP_VRF_SESSIONS: &str = "bgp_vrf_sessions";

/// The section of the neighbour detail of the VRFs.
pub const BGP_VRF_NEIGHBORS: &str = "bgp_vrf_neighbors";

/// The command of the session summary of the global table.
pub const BGP_SESSIONS_COMMAND: &str = "show bgp summary";

/// The command of the session summary of a VRF.
pub fn bgp_vrf_sessions_command(vrf: &str) -> String {
    format!("show bgp vrf {vrf} ipv4 unicast summary")
}

/// The keyword of each direction of [`bgp::DIRECTIONS`] in a command.
const DIRECTION_WORDS: [&str; 3] = ["received routes", "routes", "advertised-routes"];

/// The command of a table of a neighbour, with the index of its direction
/// in [`bgp::DIRECTIONS`].
pub fn bgp_route_command(vrf: &str, peer: Ipv4Addr, direction: usize) -> String {
    let scope = if vrf == bgp::DEFAULT_VRF {
        String::new()
    } else {
        format!("vrf {vrf} ipv4 unicast ")
    };
    format!(
        "show bgp {scope}neighbors {peer} {}",
        DIRECTION_WORDS[direction]
    )
}

/// The numbers and the ages of a session summary and of the neighbour
/// detail: the table versions, the message counters, the queues, the prefix
/// counts and the up and down times. The change hash covers the addresses
/// and the state words; the AS of a neighbour and the local AS are in the
/// running config.
const BGP_COUNTERS: &[&str] = volatile!["~#", "~#/#", "~#:#:#", "~#d#h", "~#w#d", "~#y#w", "~#h#m"];
/// The table versions of a table of a neighbour.
const BGP_ROUTES: &[&str] = volatile![
    "Table ID:",
    "BGP main routing table version",
    "BGP NSR",
    "BGP table version",
];

/// The sections of an IOS XR router with the BGP sections of the default
/// setting. A text answer keeps its raw bytes; the change hash leaves out
/// the volatile parts.
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

/// The sections of an IOS XR router with the BGP sections of a setting, in
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
            "show bgp vrf <name> ipv4 unicast summary",
            Observation,
            true,
            BGP_COUNTERS,
        ));
    }
    if capture.all() {
        out.push(text(
            bgp::NEIGHBORS,
            "show bgp neighbors",
            Observation,
            true,
            BGP_COUNTERS,
        ));
        out.push(text(
            BGP_VRF_NEIGHBORS,
            "show bgp vrf all neighbors",
            Observation,
            true,
            BGP_COUNTERS,
        ));
        out.push(text(
            bgp::ROUTES,
            "show bgp [vrf <vrf> ipv4 unicast] neighbors <address> <direction>",
            Observation,
            true,
            BGP_ROUTES,
        ));
    }
    out.sort_by_key(|s| DERIVED.contains(&s.name));
    out
}

/// The sections whose commands come from the answers of other sections.
const DERIVED: [&str; 2] = [BGP_VRF_SESSIONS, bgp::ROUTES];

/// Reads an IOS XR router.
pub struct IosxrSource {
    ssh: Arc<dyn Ssh>,
    bgp: BgpCaptures,
}

impl IosxrSource {
    pub fn new(ssh: Arc<dyn Ssh>) -> IosxrSource {
        IosxrSource {
            ssh,
            bgp: BgpCaptures::default(),
        }
    }

    /// Sets the BGP sections of a device.
    pub fn with_capture_bgp(mut self, device: &str, capture: CaptureBgp) -> IosxrSource {
        self.bgp.set(device, capture);
        self
    }
}

impl Source for IosxrSource {
    fn vendor(&self) -> Vendor {
        Vendor::Iosxr
    }

    fn sections(&self, device: &Device) -> Vec<SectionSpec> {
        sections_with(self.bgp.of(&device.id))
    }

    /// Reads the sections of the static list, then the session summary of
    /// each VRF of the `router bgp` block of the running config in name
    /// order, then the 3 tables of each IPv4 neighbour of the session
    /// summaries. A failed or absent running config makes the section
    /// [`BGP_VRF_SESSIONS`] absent, and a failed or absent summary of the
    /// global table makes the section of the tables absent, except a
    /// connect error or a timeout, which the section takes as its error, as
    /// it does when each of its commands ends in one.
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
                |spec, view| {
                    if spec.name == BGP_VRF_SESSIONS {
                        bgp::vrf_session_plan(view, bgp_vrfs, bgp_vrf_sessions_command)
                    } else {
                        bgp::text_route_plan(view, BGP_VRF_SESSIONS, bgp_route_command)
                    }
                },
            )
            .await
        })
    }
}

/// The VRFs of the `router bgp` block: the lines `vrf <name>` one space in.
fn bgp_vrfs(config: &str) -> Vec<String> {
    bgp::config_bgp_vrfs(config, |l| {
        l.strip_prefix(' ')
            .filter(|l| !l.starts_with(' '))
            .and_then(|l| l.trim_end().strip_prefix("vrf "))
            .map(str::trim)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vrfs_of_the_bgp_block_are_one_level_in() {
        let config = "Tue Nov 17 20:52:43.123 UTC\nvrf RED\n!\nrouter bgp 64500\n \
                      address-family ipv4 unicast\n !\n vrf RED\n  rd 64500:1\n  \
                      neighbor 192.0.2.2\n   remote-as 64501\n !\n vrf BLUE\n !\n!\n";
        assert_eq!(bgp_vrfs(config), ["BLUE", "RED"]);
    }

    #[test]
    fn the_commands_of_a_neighbour() {
        let p: Ipv4Addr = "192.0.2.2".parse().unwrap();
        assert_eq!(
            bgp_route_command("default", p, 0),
            "show bgp neighbors 192.0.2.2 received routes"
        );
        assert_eq!(
            bgp_route_command("RED", p, 2),
            "show bgp vrf RED ipv4 unicast neighbors 192.0.2.2 advertised-routes"
        );
    }
}
