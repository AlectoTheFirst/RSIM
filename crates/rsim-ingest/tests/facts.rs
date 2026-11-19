//! The facts of a device of each vendor on synthetic sections: the platform,
//! the OS version, the serial and the management address with their spans,
//! and the reason of each fact that is not known.

use std::collections::BTreeMap;

use rsim_core::SourceSpan;
use rsim_ingest::estate::{Input, assemble};
use rsim_ingest::facts::{DeviceFacts, Fact, Reason, Sections, device};

fn fixture(rel: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn sections(device: &str, parts: &[(&str, Vec<u8>)]) -> Sections {
    parts
        .iter()
        .map(|(n, b)| (n.to_string(), (b.clone(), format!("{device}/{n}@b1"))))
        .collect()
}

fn one(name: &str, vendor: &str, address: Option<&str>, s: &Sections) -> DeviceFacts {
    let mut all = device(name, vendor, 1_700_000_000_000, address, s);
    assert_eq!(all.len(), 1, "{all:?}");
    let (n, f) = all.remove(0);
    assert_eq!(n, name);
    assert_eq!(f.vendor, vendor);
    assert_eq!(f.collected_at, 1_700_000_000_000);
    assert_eq!(f.store_device, name);
    f
}

fn known(value: &str, span: SourceSpan) -> Fact {
    Fact::Known {
        value: value.into(),
        span: Some(span),
    }
}

fn line(file: &str, first: u32, last: u32) -> SourceSpan {
    SourceSpan::new(file, first, last)
}

const NOT_COLLECTED: Fact = Fact::Unknown(Reason::NotCollected);
const NOT_READ: Fact = Fact::Unknown(Reason::NotRead);

#[test]
fn a_vyos_router_gives_its_model_version_and_serial_from_show_version() {
    let s = sections("r1", &[("version", fixture("vyos/version.txt"))]);
    let f = one("r1", "vyos", Some("192.0.2.1"), &s);
    let file = "r1/version@b1";
    assert_eq!(f.platform, known("Fake Router 1000", line(file, 12, 12)));
    assert_eq!(f.os_version, known("1.4.0", line(file, 1, 1)));
    assert_eq!(f.serial, known("FAKER10001", line(file, 13, 13)));
    assert_eq!(
        f.management_address,
        Fact::Known {
            value: "192.0.2.1".into(),
            span: None
        }
    );
    assert_eq!(f.spans().len(), 3);
}

#[test]
fn a_vyos_router_with_no_version_section_or_no_address_has_facts_not_collected() {
    let f = one("r1", "vyos", None, &Sections::new());
    for x in [&f.platform, &f.os_version, &f.serial, &f.management_address] {
        assert_eq!(x, &NOT_COLLECTED);
    }
    assert!(f.spans().is_empty());
}

#[test]
fn an_empty_or_placeholder_vyos_serial_is_not_read_and_the_next_line_is_not_taken() {
    let text = "Version:          VyOS 1.4.0\nHardware model:   \nHardware S/N:     \nHardware UUID:    00000000-0000-4000-8000-000000000003\n";
    let s = sections("r1", &[("version", text.as_bytes().to_vec())]);
    let f = one("r1", "vyos", None, &s);
    assert_eq!(f.platform, NOT_READ);
    assert_eq!(f.serial, NOT_READ);
    assert_eq!(f.os_version, known("1.4.0", line("r1/version@b1", 1, 1)));
    for serial in ["To Be Filled By O.E.M.", "0000000000", "Default string"] {
        let text = format!("Version:          VyOS 1.4.0\nHardware S/N:     {serial}\n");
        let s = sections("r1", &[("version", text.into_bytes())]);
        assert_eq!(one("r1", "vyos", None, &s).serial, NOT_READ, "{serial}");
    }
    // A version line with no VyOS word gives no version.
    let s = sections("r1", &[("version", b"Version:          1.4.0\n".to_vec())]);
    assert_eq!(one("r1", "vyos", None, &s).os_version, NOT_READ);
}

#[test]
fn a_placeholder_platform_or_os_version_is_not_read() {
    for (model, version) in [
        ("Default string", "VyOS 0"),
        ("To Be Filled By O.E.M.", "VyOS Unknown"),
        ("System Product Name", "VyOS N/A"),
        ("Not Specified", "VyOS xxxx"),
    ] {
        let text = format!(
            "Version:          {version}\nHardware model:   {model}\nHardware S/N:     FAKER10002\n"
        );
        let s = sections("r1", &[("version", text.into_bytes())]);
        let f = one("r1", "vyos", None, &s);
        assert_eq!(f.platform, NOT_READ, "{model}");
        assert_eq!(f.os_version, NOT_READ, "{version}");
        assert_eq!(f.serial, known("FAKER10002", line("r1/version@b1", 3, 3)));
    }
    let json = br#"{"chassis_id": "System Product Name", "nxos_ver_str": "System Version", "proc_board_id": "FAKELEAF02"}"#;
    let s = sections("leaf1", &[("version", json.to_vec())]);
    let f = one("leaf1", "nxos", None, &s);
    assert_eq!(f.platform, NOT_READ);
    assert_eq!(f.os_version, NOT_READ);
    assert_eq!(f.serial.value(), Some("FAKELEAF02"));
}

#[test]
fn an_nxos_switch_gives_its_chassis_version_and_board_serial() {
    let s = sections("leaf1", &[("version", fixture("nxos/version.json"))]);
    let f = one("leaf1", "nxos", Some("192.0.2.11"), &s);
    assert_eq!(f.platform.value(), Some("Nexus9000 FAKE-48 chassis"));
    assert_eq!(f.os_version.value(), Some("9.3(8)"));
    assert_eq!(f.serial.value(), Some("FAKELEAF01"));
    for x in [&f.platform, &f.os_version, &f.serial] {
        let span = x.span().unwrap();
        assert_eq!(&*span.file, "leaf1/version@b1");
        assert!(!span.is_row());
    }
    // `sys_ver_str` gives the version when `nxos_ver_str` is not there, and
    // a placeholder board serial is not read.
    let json = br#"{"sys_ver_str": "7.0(3)I7(9)", "proc_board_id": "00000000"}"#;
    let s = sections("leaf1", &[("version", json.to_vec())]);
    let f = one("leaf1", "nxos", None, &s);
    assert_eq!(f.os_version.value(), Some("7.0(3)I7(9)"));
    assert_eq!(f.serial, NOT_READ);
    assert_eq!(f.platform, NOT_READ);
    // A section that is not JSON gives no fact.
    let s = sections("leaf1", &[("version", b"% Invalid command".to_vec())]);
    let f = one("leaf1", "nxos", None, &s);
    assert_eq!(f.os_version, NOT_READ);
}

#[test]
fn an_iosxr_router_gives_its_version_and_the_pid_and_serial_of_its_chassis_row() {
    let s = sections(
        "xr1",
        &[
            ("version", fixture("iosxr/version.txt")),
            ("inventory", fixture("iosxr/inventory.txt")),
        ],
    );
    let f = one("xr1", "iosxr", Some("192.0.2.21"), &s);
    assert_eq!(f.os_version.value(), Some("7.11.2"));
    assert_eq!(&*f.os_version.span().unwrap().file, "xr1/version@b1");
    let chassis = line("xr1/inventory@b1", 5, 6);
    assert_eq!(f.platform, known("FAKE-XR-CHASSIS", chassis.clone()));
    assert_eq!(f.serial, known("FAKEXR0001", chassis));
    // With no inventory section, the chassis facts are not collected.
    let s = sections("xr1", &[("version", fixture("iosxr/version.txt"))]);
    let f = one("xr1", "iosxr", None, &s);
    assert_eq!(f.platform, NOT_COLLECTED);
    assert_eq!(f.serial, NOT_COLLECTED);
    assert_eq!(f.os_version.value(), Some("7.11.2"));
    // An inventory with no chassis row gives no chassis fact.
    let inventory = b"NAME: \"0/RP0/CPU0\", DESCR: \"Fake Route Processor\"\nPID: FAKE-XR-RP, VID: V01, SN: FAKEXR0002\n";
    let s = sections("xr1", &[("inventory", inventory.to_vec())]);
    let f = one("xr1", "iosxr", None, &s);
    assert_eq!(f.platform, NOT_READ);
    assert_eq!(f.serial, NOT_READ);
    assert_eq!(f.os_version, NOT_COLLECTED);
}

#[test]
fn an_iosxe_device_gives_its_version_hardware_and_board_serial() {
    let s = sections("xe1", &[("version", fixture("iosxe/version.txt"))]);
    let f = one("xe1", "iosxe", Some("192.0.2.31"), &s);
    assert_eq!(f.os_version.value(), Some("17.9.4a"));
    assert_eq!(f.platform.value(), Some("FAKE-XE-1000"));
    assert_eq!(f.serial.value(), Some("FAKEXE0001"));
    assert_eq!(&*f.serial.span().unwrap().file, "xe1/version@b1");
    // A version with no hardware line and no board line.
    let text = "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc3)\n";
    let s = sections("xe1", &[("version", text.as_bytes().to_vec())]);
    let f = one("xe1", "iosxe", None, &s);
    assert_eq!(f.os_version.value(), Some("17.9.4a"));
    assert_eq!(f.platform, NOT_READ);
    assert_eq!(f.serial, NOT_READ);
}

#[test]
fn a_vendor_with_no_reader_has_facts_not_read() {
    let f = one("fw1", "fortios", Some("192.0.2.41"), &Sections::new());
    assert_eq!(f.platform, NOT_READ);
    assert_eq!(f.serial, NOT_READ);
    assert_eq!(f.management_address.value(), Some("192.0.2.41"));
}

fn unifi_sections() -> Sections {
    ["networks", "wlans", "devices", "clients", "port_profiles"]
        .iter()
        .map(|n| {
            (
                n.to_string(),
                (fixture(&format!("unifi/{n}.json")), format!("site1/{n}@b1")),
            )
        })
        .collect()
}

#[test]
fn a_unifi_console_gives_the_facts_of_each_device_record_by_its_twin_device() {
    let s = unifi_sections();
    let all: BTreeMap<String, DeviceFacts> = device("site1", "unifi", 7, Some("192.0.2.51"), &s)
        .into_iter()
        .collect();
    assert_eq!(
        all.keys().collect::<Vec<_>>(),
        ["ap1", "gw1", "sw1"],
        "the console has no entry of its own"
    );
    let row = |n: u32| SourceSpan::row("site1/devices@b1", n);
    let sw = &all["sw1"];
    assert_eq!(sw.vendor, "unifi");
    assert_eq!(sw.collected_at, 7);
    assert_eq!(sw.store_device, "site1");
    assert_eq!(sw.platform, known("USW-FAKE-8", row(1)));
    assert_eq!(sw.os_version, known("7.1.26.15869", row(1)));
    assert_eq!(sw.serial, known("FAKESW0001", row(1)));
    assert_eq!(sw.management_address, known("198.51.100.11", row(1)));
    // A placeholder serial is not read.
    assert_eq!(all["ap1"].serial, NOT_READ);
    assert_eq!(all["ap1"].platform, known("U6-FAKE", row(2)));
    // A record with no key gives no fact.
    let gw = &all["gw1"];
    for x in [
        &gw.platform,
        &gw.os_version,
        &gw.serial,
        &gw.management_address,
    ] {
        assert_eq!(x, &NOT_READ);
    }
    // The switch and the access point are devices of the twin of the site
    // by the same names; the gateway record is a device that the site
    // lowering does not lower.
    let twin = assemble(vec![Input::Unifi {
        name: "site1".into(),
        sections: s,
    }])
    .builder
    .build()
    .unwrap();
    let devices: Vec<String> = twin.devices().iter().map(ToString::to_string).collect();
    assert_eq!(devices, ["ap1", "sw1"]);
}

#[test]
fn a_unifi_console_with_no_devices_section_gives_its_own_entry() {
    let f = one("site1", "unifi", Some("192.0.2.51"), &Sections::new());
    assert_eq!(f.platform, NOT_COLLECTED);
    assert_eq!(f.serial, NOT_COLLECTED);
    assert_eq!(f.management_address.value(), Some("192.0.2.51"));
}
