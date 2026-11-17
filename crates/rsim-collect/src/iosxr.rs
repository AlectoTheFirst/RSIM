//! The IOS XR source: read-only `show` commands over SSH, each answer as
//! text. The commands are the commands of the HST collector, which has not
//! run against a live IOS XR router; they are not confirmed on a device.

use std::sync::Arc;
use std::time::Duration;

use rsim_store::{Class, Format};

use crate::cli::CliRules;
use crate::{BoxFuture, Device, RawSection, SectionSpec, Source, Ssh, Vendor, fetch_sections};

/// The CLI rules of IOS XR: the Cisco rules.
pub const RULES: CliRules = CliRules::CISCO;

/// The setup commands of a shell on IOS XR.
pub const SHELL_SETUP: [&str; 2] = ["terminal length 0", "terminal width 512"];

/// IOS XR prints the time of the command before each answer, for example
/// `Tue Nov 17 20:52:43.123 UTC`. These line starts remove it from the
/// change hash. The configuration has its own time lines.
const TIME_LINES: &[&str] = &["Mon ", "Tue ", "Wed ", "Thu ", "Fri ", "Sat ", "Sun "];
const CONFIG_TIME_LINES: &[&str] = &[
    "Mon ",
    "Tue ",
    "Wed ",
    "Thu ",
    "Fri ",
    "Sat ",
    "Sun ",
    "Building configuration",
    "!! IOS XR Configuration",
    "!! Last configuration change",
];

/// One section of the static list: the name, the command, the class and
/// whether a device can refuse it.
const SPECS: &[(&str, &str, Class, bool)] = {
    use Class::{Configuration, Observation};
    &[
        ("config", "show running-config", Configuration, false),
        ("version", "show version", Configuration, false),
        ("interfaces", "show interfaces", Observation, false),
        ("lldp", "show lldp neighbors detail", Observation, true),
        ("cdp", "show cdp neighbors detail", Observation, true),
        ("vrfs", "show vrf all detail", Configuration, false),
        ("rib", "show route vrf all ipv4", Observation, false),
        ("arp", "show arp vrf all", Observation, true),
        ("inventory", "show inventory", Configuration, true),
        ("hsrp", "show hsrp", Observation, true),
    ]
};

/// The sections of an IOS XR router. A text answer keeps its raw bytes;
/// the time lines are volatile.
pub fn sections() -> Vec<SectionSpec> {
    SPECS
        .iter()
        .map(|(name, command, class, optional)| SectionSpec {
            name,
            command: (*command).to_string(),
            class: *class,
            format: Format::Text,
            volatile: if *name == "config" {
                CONFIG_TIME_LINES
            } else {
                TIME_LINES
            },
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
