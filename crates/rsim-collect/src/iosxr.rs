//! The IOS XR source: read-only `show` commands over SSH, each answer as
//! text. The commands are the commands of the HST collector, which has not
//! run against a live IOS XR router; they are not confirmed on a device.

use std::sync::Arc;

use rsim_store::{Class, Format};

use crate::cli::CliRules;
use crate::{
    BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Timeouts, Vendor, fetch_sections,
};

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

/// The sections of an IOS XR router. A text answer keeps its raw bytes;
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

/// Reads an IOS XR router.
pub struct IosxrSource {
    ssh: Arc<dyn Ssh>,
}

impl IosxrSource {
    pub fn new(ssh: Arc<dyn Ssh>) -> IosxrSource {
        IosxrSource { ssh }
    }
}

impl Source for IosxrSource {
    fn vendor(&self) -> Vendor {
        Vendor::Iosxr
    }

    fn sections(&self, _device: &Device) -> Vec<SectionSpec> {
        sections()
    }

    fn fetch<'a>(
        &'a self,
        device: &'a Device,
        timeouts: Timeouts,
    ) -> BoxFuture<'a, Vec<RawSection>> {
        Box::pin(async move {
            let serial = self.ssh.serial(device);
            let read = |command: String| -> BoxFuture<'a, _> {
                let ssh = self.ssh.clone();
                Box::pin(async move { ssh.run(device, &command).await })
            };
            let mut out = fetch_sections(self.sections(device), timeouts, serial, read).await;
            RULES.apply(&mut out, self.ssh.banner_each_command(device));
            out
        })
    }
}
