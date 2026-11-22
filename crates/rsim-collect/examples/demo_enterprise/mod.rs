//! The generator of the demo estate: the command replies of each device in
//! each cycle, in the layout that `rsim_collect::demo` reads.

pub mod build;
pub mod iosxe;
pub mod iosxr;
pub mod model;
pub mod nxos;
pub mod route;

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use rsim_collect::demo::{COMMANDS, DEVICES, cycle_dir};
use rsim_collect::{CaptureBgp, SectionSpec};
use rsim_store::Format;

use model::{Estate, Os};

/// The number of cycles.
pub const CYCLES: usize = 3;

/// The files of each device, by device and file name.
type Files = BTreeMap<String, BTreeMap<String, Vec<u8>>>;

/// True for a section whose commands come from the answers of other
/// sections, and for the sessions of the global table of NX-OS, which the
/// source sends only when the switch refuses the sessions of all VRFs.
fn derived(s: &SectionSpec) -> bool {
    s.command.contains('<')
        || s.command.contains('[')
        || s.name == rsim_collect::nxos::BGP_SESSIONS_DEFAULT
}

fn file_name(s: &SectionSpec) -> String {
    let ext = if s.format == Format::Json {
        "json"
    } else {
        "txt"
    };
    format!("{}.{ext}", s.name)
}

/// The files of a device: a reply for each command that its source sends,
/// and the list of the commands.
fn device_files(e: &Estate, t: &route::Tables, d: usize) -> BTreeMap<String, Vec<u8>> {
    let dev = &e.devs[d];
    let (specs, mut replies, vrfs) = match dev.os {
        Os::Nxos => (
            rsim_collect::nxos::sections_with(false, CaptureBgp::Sessions),
            nxos::render(e, t, d),
            BTreeMap::new(),
        ),
        Os::Iosxe => {
            let (r, v) = iosxe::render(e, t, d);
            (
                rsim_collect::iosxe::sections_with(CaptureBgp::Sessions),
                r,
                v,
            )
        }
        Os::Iosxr => (
            rsim_collect::iosxr::sections_with(CaptureBgp::Sessions),
            iosxr::render(e, t, d),
            BTreeMap::new(),
        ),
    };
    let mut files = BTreeMap::new();
    let mut commands = String::new();
    for s in specs.iter().filter(|s| !derived(s)) {
        let text = replies
            .remove(s.name)
            .unwrap_or_else(|| panic!("{}: no reply of {}", dev.name, s.name));
        let f = file_name(s);
        commands.push_str(&format!("{f}\t{}\n", s.command));
        files.insert(f, text.into_bytes());
    }
    for (vrf, text) in vrfs {
        let f = format!("{}.{vrf}.txt", rsim_collect::iosxe::ARP_VRFS);
        commands.push_str(&format!(
            "{f}\t{}\n",
            rsim_collect::iosxe::arp_vrf_command(&vrf)
        ));
        files.insert(f, text.into_bytes());
    }
    assert!(
        replies.is_empty(),
        "{}: replies with no command: {:?}",
        dev.name,
        replies.keys()
    );
    files.insert(COMMANDS.to_string(), commands.into_bytes());
    files
}

/// The files of each device in a cycle, and the list of the devices.
fn cycle(n: usize) -> (Files, String) {
    let e = build::estate(n);
    let t = route::tables(&e);
    let mut files = Files::new();
    let mut devices = String::new();
    let mut order: Vec<usize> = (0..e.devs.len()).collect();
    order.sort_by(|a, b| e.devs[*a].name.cmp(&e.devs[*b].name));
    for d in order {
        let dev = &e.devs[d];
        devices.push_str(&format!("{} {} {}\n", dev.name, dev.os.vendor(), dev.mgmt));
        files.insert(dev.name.clone(), device_files(&e, &t, d));
    }
    (files, devices)
}

/// Writes the demo folder: the list of the devices, all files of cycle 1,
/// and in each later cycle the files that differ from the cycle before it.
/// The files of an earlier run in the folder are replaced.
pub fn generate(out: &Path) -> io::Result<()> {
    std::fs::create_dir_all(out)?;
    for entry in std::fs::read_dir(out)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("cycle-") {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    let mut before: Option<Files> = None;
    for n in 1..=CYCLES {
        let (files, devices) = cycle(n);
        if n == 1 {
            std::fs::write(out.join(DEVICES), devices)?;
        }
        let dir = out.join(cycle_dir(n));
        for (device, list) in &files {
            for (name, bytes) in list {
                let same = before
                    .as_ref()
                    .and_then(|b| b.get(device))
                    .and_then(|b| b.get(name))
                    .is_some_and(|b| b == bytes);
                if same {
                    continue;
                }
                std::fs::create_dir_all(dir.join(device))?;
                std::fs::write(dir.join(device).join(name), bytes)?;
            }
        }
        std::fs::create_dir_all(&dir)?;
        before = Some(files);
    }
    Ok(())
}
