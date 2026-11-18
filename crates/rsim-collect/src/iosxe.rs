//! The IOS XE source: read-only `show` commands over SSH, each answer as
//! text. `show ip arp` gives the ARP table of the global routing table
//! only.

use std::sync::Arc;
use std::time::Duration;

use rsim_store::{Class, Format};

use crate::cli::CliRules;
use crate::{BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Vendor, fetch_sections};

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
const VERSION: &[&str] = &[
    "=*uptime is",
    "Uptime for this control processor",
    "System returned to ROM",
    "System restarted at",
    "Last reload",
];
/// The counters, the rates and the times of the last packets.
const INTERFACES: &[&str] = &[
    "=# ",
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
const NONE: &[&str] = &[];

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
        ("vrfs", "show vrf detail", Configuration, true, NONE),
        ("rib", "show ip route vrf *", Observation, false, ROUTES),
        ("rib_global", "show ip route", Observation, false, ROUTES),
        ("arp", "show ip arp", Observation, true, ARP),
        ("acls", "show ip access-lists", Configuration, true, ACLS),
        ("inventory", "show inventory", Configuration, true, NONE),
        ("hsrp", "show standby brief", Observation, true, NONE),
        ("vrrp", "show vrrp brief", Observation, true, NONE),
    ]
};

/// The sections of an IOS XE router. A text answer keeps its raw bytes;
/// the change hash leaves out the volatile parts.
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

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeout: Duration,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let serial = self.ssh.serial(device);
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            let mut out = fetch_sections(self.sections(device), timeout, serial, read).await;
            RULES.apply(&mut out, self.ssh.banner_each_command(device));
            out
        })
    }
}
