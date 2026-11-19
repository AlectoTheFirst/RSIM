//! The facts of each device of a snapshot: the vendor, the platform, the OS
//! version, the serial, the management address and the time of the
//! manifest. A fact that is read keeps the source span of its line or row;
//! a fact that is not known has the reason `not_collected` or `not_read`.

use std::collections::BTreeMap;

use rsim_core::SourceSpan;
use rsim_store::{Snapshot, Store, StoreError};
use serde_json::Value;

use crate::stanza::read_json;
use crate::{iosxe, iosxr, unifi, vyos};

/// Why a fact is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The snapshot has no section or record that gives the fact.
    NotCollected,
    /// The section is in the snapshot, but no reader gives the fact from
    /// it: the line or the key is not there, the template does not read
    /// it, or the value is a placeholder.
    NotRead,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Reason::NotCollected => "not_collected",
            Reason::NotRead => "not_read",
        }
    }
}

/// One fact of a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fact {
    /// The value with the span from which it came. The management address
    /// of a manifest has no span.
    Known {
        value: String,
        span: Option<SourceSpan>,
    },
    Unknown(Reason),
}

impl Fact {
    /// The value, or `None` when the fact is not known.
    pub fn value(&self) -> Option<&str> {
        match self {
            Fact::Known { value, .. } => Some(value),
            Fact::Unknown(_) => None,
        }
    }

    /// The reason, or `None` when the fact is known.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Fact::Known { .. } => None,
            Fact::Unknown(r) => Some(*r),
        }
    }

    pub fn span(&self) -> Option<&SourceSpan> {
        match self {
            Fact::Known { span, .. } => span.as_ref(),
            Fact::Unknown(_) => None,
        }
    }

    /// The trimmed text with its span, or `not_read` for no text or an
    /// empty text.
    fn of(text: Option<&str>, span: SourceSpan) -> Fact {
        match text.map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => Fact::Known {
                value: t.to_string(),
                span: Some(span),
            },
            None => Fact::Unknown(Reason::NotRead),
        }
    }

    /// A serial with its span, or `not_read` for no text or a placeholder.
    fn serial(text: Option<&str>, span: SourceSpan) -> Fact {
        match text {
            Some(t) if placeholder_serial(t) => Fact::Unknown(Reason::NotRead),
            _ => Fact::of(text, span),
        }
    }

    /// A platform or an OS version with its span, or `not_read` for no
    /// text or a placeholder.
    fn named(text: Option<&str>, span: SourceSpan) -> Fact {
        match text {
            Some(t) if placeholder_text(t) => Fact::Unknown(Reason::NotRead),
            _ => Fact::of(text, span),
        }
    }
}

/// The facts of one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceFacts {
    /// The vendor of the device manifest.
    pub vendor: String,
    /// The model of the device.
    pub platform: Fact,
    pub os_version: Fact,
    /// The serial of the chassis.
    pub serial: Fact,
    /// The address to which the collector connected, or for a UniFi device
    /// the address of its record.
    pub management_address: Fact,
    /// The time of the device manifest, in milliseconds since the Unix
    /// epoch.
    pub collected_at: u64,
}

impl DeviceFacts {
    /// The spans of the known facts in column order, each span once.
    pub fn spans(&self) -> Vec<&SourceSpan> {
        let mut out: Vec<&SourceSpan> = Vec::new();
        for s in [
            &self.platform,
            &self.os_version,
            &self.serial,
            &self.management_address,
        ]
        .into_iter()
        .filter_map(Fact::span)
        {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }
}

/// The serials that name no chassis, compared in lower case with each run
/// of white space as one space: what the firmware of a whitebox board or of
/// a virtual machine gives when the field is not set.
pub const PLACEHOLDER_SERIALS: &[&str] = &[
    "",
    "-",
    "none",
    "unknown",
    "n/a",
    "na",
    "not specified",
    "not applicable",
    "not available",
    "default string",
    "to be filled by o.e.m.",
    "o.e.m.",
    "oem",
    "system serial number",
    "chassis serial number",
    "base board serial number",
    "serial number",
    "serialnumber",
    "invalid",
    "empty",
    "undefined",
    "default",
    "0123456789",
    "123456789",
    "1234567890",
    "12345678",
];

/// The platforms and OS versions that name no model and no version,
/// compared as [`PLACEHOLDER_SERIALS`]: what the firmware of a board gives
/// when the field is not set.
pub const PLACEHOLDER_TEXTS: &[&str] = &[
    "",
    "default string",
    "to be filled by o.e.m.",
    "system product name",
    "system version",
    "not specified",
    "none",
    "n/a",
    "0",
    "unknown",
];

/// The text in lower case with each run of white space as one space, and
/// the count of its characters other than white space with true if they
/// are all one character.
fn folded(text: &str) -> (String, usize, bool) {
    let words: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
    let mut chars = words.iter().flat_map(|w| w.chars());
    let first = chars.next();
    let mut count = usize::from(first.is_some());
    let mut one = true;
    for c in chars {
        count += 1;
        one &= Some(c) == first;
    }
    (words.join(" "), count, one)
}

/// True if a serial is a placeholder: one of [`PLACEHOLDER_SERIALS`], or
/// one character repeated, such as `0000` or `XXXXXXXX`.
pub fn placeholder_serial(text: &str) -> bool {
    let (joined, _, one) = folded(text);
    one || PLACEHOLDER_SERIALS.contains(&joined.as_str())
}

/// True if a platform or an OS version is a placeholder: one of
/// [`PLACEHOLDER_TEXTS`], or one character 2 or more times, such as `xx`
/// or `....`.
pub fn placeholder_text(text: &str) -> bool {
    let (joined, count, one) = folded(text);
    (one && count >= 2) || PLACEHOLDER_TEXTS.contains(&joined.as_str())
}

/// The sections of a device, each with its file name.
pub type Sections = BTreeMap<String, (Vec<u8>, String)>;

/// The sections that the facts of a vendor read.
pub fn sections(vendor: &str) -> &'static [&'static str] {
    match vendor {
        "vyos" | "nxos" | "iosxe" => &["version"],
        "iosxr" => &["version", "inventory"],
        "unifi" => &["devices"],
        _ => &[],
    }
}

/// The platform, the OS version and the serial of a device.
struct Identity {
    platform: Fact,
    os_version: Fact,
    serial: Fact,
}

impl Identity {
    fn all(r: Reason) -> Identity {
        Identity {
            platform: Fact::Unknown(r),
            os_version: Fact::Unknown(r),
            serial: Fact::Unknown(r),
        }
    }
}

/// The facts of one device manifest, by twin device. A UniFi console gives
/// one entry for each device record of its `devices` section, by the name
/// that the lowering gives the device, and an entry of its own only when
/// the section gives no device. Each other device gives one entry.
pub fn device(
    name: &str,
    vendor: &str,
    collected_at: u64,
    management_address: Option<&str>,
    sections: &Sections,
) -> Vec<(String, DeviceFacts)> {
    let address = match management_address {
        Some(a) => Fact::Known {
            value: a.to_string(),
            span: None,
        },
        None => Fact::Unknown(Reason::NotCollected),
    };
    let get = |n: &str| sections.get(n).map(|(b, f)| (b.as_slice(), f.as_str()));
    let facts = |id: Identity, management_address: Fact| DeviceFacts {
        vendor: vendor.to_string(),
        platform: id.platform,
        os_version: id.os_version,
        serial: id.serial,
        management_address,
        collected_at,
    };
    let id = match vendor {
        "vyos" => get("version").map_or(Identity::all(Reason::NotCollected), |(b, f)| {
            vyos_version(b, f)
        }),
        "nxos" => get("version").map_or(Identity::all(Reason::NotCollected), |(b, f)| {
            nxos_version(b, f)
        }),
        "iosxr" => iosxr_version(get("version"), get("inventory")),
        "iosxe" => get("version").map_or(Identity::all(Reason::NotCollected), |(b, f)| {
            iosxe_version(b, f)
        }),
        "unifi" => {
            let Some((b, f)) = get("devices") else {
                return vec![(
                    name.to_string(),
                    facts(Identity::all(Reason::NotCollected), address),
                )];
            };
            let records = unifi_devices(b, f);
            if records.is_empty() {
                return vec![(
                    name.to_string(),
                    facts(Identity::all(Reason::NotRead), address),
                )];
            }
            return records
                .into_iter()
                .map(|(d, id, ip)| (d, facts(id, ip)))
                .collect();
        }
        _ => Identity::all(Reason::NotRead),
    };
    vec![(name.to_string(), facts(id, address))]
}

/// The facts of each device of a snapshot, by twin device.
pub fn of_snapshot(
    store: &Store,
    snap: &Snapshot,
) -> Result<BTreeMap<String, DeviceFacts>, StoreError> {
    let mut out = BTreeMap::new();
    for (name, m) in &snap.devices {
        let mut s = Sections::new();
        for section in sections(&m.vendor) {
            if let Some(b) = m.section(section).and_then(|e| e.blob) {
                let short: String = b.to_string().chars().take(12).collect();
                s.insert(
                    (*section).to_string(),
                    (store.read_blob(&b)?, format!("{name}/{section}@{short}")),
                );
            }
        }
        out.extend(device(
            name,
            &m.vendor,
            m.collected_at,
            m.management_address.as_deref(),
            &s,
        ));
    }
    Ok(out)
}

/// The line of a text section that starts with a label, with the rest of
/// the line and its span.
fn labelled<'a>(text: &'a str, file: &str, label: &str) -> Option<(&'a str, SourceSpan)> {
    rsim_textfsm::split_lines(text)
        .enumerate()
        .find_map(|(i, l)| {
            let rest = l.strip_prefix(label)?;
            let n = u32::try_from(i + 1).unwrap_or(u32::MAX);
            Some((rest, SourceSpan::new(file, n, n)))
        })
}

/// VyOS `show version`: the word after `VyOS` on the version line, and the
/// rest of the hardware model line and of the serial line.
fn vyos_version(bytes: &[u8], file: &str) -> Identity {
    let text = String::from_utf8_lossy(bytes);
    let fact = |label: &str, serial: bool| match labelled(&text, file, label) {
        Some((rest, span)) if serial => Fact::serial(Some(rest), span),
        Some((rest, span)) => Fact::named(Some(rest), span),
        None => Fact::Unknown(Reason::NotRead),
    };
    let os_version = match labelled(&text, file, vyos::profile::VERSION_LINE) {
        Some((rest, span)) => {
            let mut w = rest.split_whitespace();
            let v = match w.next() {
                Some(word) if word == vyos::profile::VERSION_NAME => w.next(),
                _ => None,
            };
            Fact::named(v, span)
        }
        None => Fact::Unknown(Reason::NotRead),
    };
    Identity {
        platform: fact(vyos::profile::MODEL_LINE, false),
        os_version,
        serial: fact(vyos::profile::SERIAL_LINE, true),
    }
}

/// NX-OS `show version | json`: `chassis_id`, `nxos_ver_str` else
/// `sys_ver_str`, and `proc_board_id`, each with the lines of its key in
/// the canonical form.
fn nxos_version(bytes: &[u8], file: &str) -> Identity {
    let Ok(doc) = read_json(bytes) else {
        return Identity::all(Reason::NotRead);
    };
    let key = |k: &str| {
        let s = doc.root.get(k)?;
        let t = s
            .text()
            .map(str::trim)
            .filter(|t| !t.is_empty() && *t != "null")?;
        Some((t, SourceSpan::new(file, s.first_line, s.last_line)))
    };
    let fact = |keys: &[&str], serial: bool| match keys.iter().find_map(|k| key(k)) {
        Some((t, span)) if serial => Fact::serial(Some(t), span),
        Some((t, span)) => Fact::named(Some(t), span),
        None => Fact::Unknown(Reason::NotRead),
    };
    Identity {
        platform: fact(&["chassis_id"], false),
        os_version: fact(&["nxos_ver_str", "sys_ver_str"], false),
        serial: fact(&["proc_board_id"], true),
    }
}

/// IOS-XR: the version of `show version`, and the PID and the serial of
/// the chassis row of `show inventory`.
fn iosxr_version(version: Option<(&[u8], &str)>, inventory: Option<(&[u8], &str)>) -> Identity {
    let os_version = match version {
        None => Fact::Unknown(Reason::NotCollected),
        Some((b, f)) => match iosxr::state::parse("show version", b, f) {
            Ok(p) => p
                .records()
                .find_map(|(r, span)| match p.text(r, "VERSION").trim() {
                    "" => None,
                    v => Some(Fact::named(Some(v), span)),
                })
                .unwrap_or(Fact::Unknown(Reason::NotRead)),
            Err(_) => Fact::Unknown(Reason::NotRead),
        },
    };
    let (platform, serial) = match inventory {
        None => (
            Fact::Unknown(Reason::NotCollected),
            Fact::Unknown(Reason::NotCollected),
        ),
        Some((b, f)) => match iosxr::state::parse("show inventory", b, f) {
            Ok(p) => p
                .records()
                .find(|(r, _)| p.text(r, "NAME") == iosxr::profile::CHASSIS_ENTRY)
                .map_or(
                    (
                        Fact::Unknown(Reason::NotRead),
                        Fact::Unknown(Reason::NotRead),
                    ),
                    |(r, span)| {
                        (
                            Fact::named(Some(p.text(r, "PID")), span.clone()),
                            Fact::serial(Some(p.text(r, "SN")), span),
                        )
                    },
                ),
            Err(_) => (
                Fact::Unknown(Reason::NotRead),
                Fact::Unknown(Reason::NotRead),
            ),
        },
    };
    Identity {
        platform,
        os_version,
        serial,
    }
}

/// IOS-XE `show version`: `VERSION`, the first `HARDWARE` and the first
/// `SERIAL` of the template.
fn iosxe_version(bytes: &[u8], file: &str) -> Identity {
    let Ok(p) = iosxe::state::parse_command("show version", bytes, file) else {
        return Identity::all(Reason::NotRead);
    };
    let Some((r, span)) = p.records().next() else {
        return Identity::all(Reason::NotRead);
    };
    let first = |name: &str| p.list(r, name).into_iter().next();
    Identity {
        platform: Fact::named(first("HARDWARE").as_deref(), span.clone()),
        os_version: Fact::named(Some(p.text(r, "VERSION")), span.clone()),
        serial: Fact::serial(first("SERIAL").as_deref(), span),
    }
}

/// The device records of a UniFi `devices` section: the name that the
/// lowering gives each device, its model, version and serial, and its
/// address, each with the row span of its record.
fn unifi_devices(bytes: &[u8], file: &str) -> Vec<(String, Identity, Fact)> {
    let v: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let site = unifi::read(&Value::Null, &Value::Null, &v, &Value::Null);
    let records = unifi::site::items(&v);
    site.devices
        .iter()
        .filter_map(|d| {
            let x = records.get(d.index)?;
            let span = SourceSpan::row(file, u32::try_from(d.index + 1).unwrap_or(u32::MAX));
            let s = |k: &str| x.get(k).and_then(Value::as_str);
            Some((
                unifi::lower::device_name(d),
                Identity {
                    platform: Fact::named(s("model"), span.clone()),
                    os_version: Fact::named(s("version"), span.clone()),
                    serial: Fact::serial(s("serial"), span.clone()),
                },
                Fact::of(s("ip"), span),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_placeholder_serial_is_not_a_serial() {
        for s in [
            "",
            "  ",
            "To Be Filled By O.E.M.",
            "0000",
            "XXXXXXXX",
            "n/a",
            "x x",
        ] {
            assert!(placeholder_serial(s), "{s:?}");
        }
        for s in ["FAKE0001", "AB", "0001"] {
            assert!(!placeholder_serial(s), "{s:?}");
        }
    }

    #[test]
    fn a_placeholder_platform_or_version_is_not_a_value() {
        for s in [
            "Default string",
            "To be filled by O.E.M.",
            "To Be Filled By O.E.M.",
            "System Product Name",
            "System Version",
            "Not Specified",
            "None",
            "N/A",
            "0",
            "Unknown",
            "",
            "   ",
            "xx",
            "....",
        ] {
            assert!(placeholder_text(s), "{s:?}");
        }
        for s in ["Fake Router 1000", "1.4.0", "9", "X", "U6-FAKE"] {
            assert!(!placeholder_text(s), "{s:?}");
        }
    }
}
