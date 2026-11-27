//! The identity of a twin: a base and an ordered list of what-if layers.
//!
//! The identifier grammar: `builtin.<topology>` for a hand-built topology of the tests,
//! `snapshot-YYYY-MM-DD-HHMMSS` for a snapshot of the store, named by its UTC second, and
//! `snapshot-YYYY-MM-DD-HHMMSS~<scenario>~<hash>` for a scenario on a snapshot. A name is
//! lower-case letters, digits and `-`, so `.` and `~` only separate the parts. An unnamed
//! scenario has an empty `<scenario>`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Twin
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TwinJson {
    /// Twin
    pub id: String,
    /// Base
    pub base: String,
    /// Snapshot time
    pub snapshot: Option<String>,
    /// Layers
    pub layers: Vec<String>,
}

/// True if `name` is a name of the grammar: lower-case letters, digits and
/// `-`, not empty.
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The prefix of the name of a snapshot.
const PREFIX: &str = "snapshot-";

/// The UTC date and time of a second since the Unix epoch: the year, the
/// month, the day, the hour, the minute and the second.
fn utc(second: u64) -> (u64, u64, u64, u64, u64, u64) {
    let (days, rest) = (second / 86_400, second % 86_400);
    // The civil date of a day number, with years that start on 1 March.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day, rest / 3_600, rest % 3_600 / 60, rest % 60)
}

/// The second since the Unix epoch of a UTC date and time from 1970, with no
/// check of the ranges of its parts.
fn second_of(year: u64, month: u64, day: u64, h: u64, m: u64, s: u64) -> Option<u64> {
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = y / 400;
    let yoe = y % 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day.checked_sub(1)?;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + h * 3_600 + m * 60 + s)
}

/// The name of the snapshot of a time in milliseconds since the Unix epoch:
/// `snapshot-YYYY-MM-DD-HHMMSS` of its UTC second.
pub fn snapshot_name(time_ms: u64) -> String {
    let (y, mo, d, h, mi, s) = utc(time_ms / 1000);
    format!("{PREFIX}{y:04}-{mo:02}-{d:02}-{h:02}{mi:02}{s:02}")
}

/// The UTC time of a time in milliseconds since the Unix epoch in RFC 3339,
/// to the second.
pub fn utc_time(time_ms: u64) -> String {
    let (y, mo, d, h, mi, s) = utc(time_ms / 1000);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// The second since the Unix epoch of a snapshot name, or `None` for a text
/// that is not the name of a second.
pub fn snapshot_second(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(PREFIX)?;
    let b = rest.as_bytes();
    if b.len() != 17 || b[4] != b'-' || b[7] != b'-' || b[10] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let t = rest.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())
            .flatten()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(13..15)?, num(15..17)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let second = second_of(y, mo, d, h, mi, s)?;
    (snapshot_name(second * 1000) == name).then_some(second)
}

impl TwinJson {
    /// The twin of a hand-built topology of the tests, or an error for a name that is not
    /// a name of the grammar.
    pub fn builtin(topology: &str) -> Result<TwinJson, String> {
        if !is_name(topology) {
            return Err(format!(
                "{topology:?} is not a twin name: lower-case letters, digits and -"
            ));
        }
        let id = format!("builtin.{topology}");
        Ok(TwinJson {
            id: id.clone(),
            base: id,
            snapshot: None,
            layers: Vec::new(),
        })
    }

    /// The twin of the snapshot of the store at a time in milliseconds
    /// since the Unix epoch.
    pub fn snapshot(time_ms: u64) -> TwinJson {
        let id = snapshot_name(time_ms);
        TwinJson {
            id: id.clone(),
            base: id,
            snapshot: Some(utc_time(time_ms)),
            layers: Vec::new(),
        }
    }

    /// The twin of an unnamed scenario: the snapshot of the store at a time
    /// in milliseconds since the Unix epoch, with the text of each layer in
    /// order. The identifier is `<snapshot>~~<hash>`, where `<hash>` is the
    /// first 12 hex digits of the 64-bit FNV-1a hash of the layer texts,
    /// each text followed by a line feed.
    pub fn scenario(time_ms: u64, layers: Vec<String>) -> TwinJson {
        let base = snapshot_name(time_ms);
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for b in layers.iter().flat_map(|l| l.bytes().chain([b'\n'])) {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let hex = format!("{hash:016x}");
        TwinJson {
            id: format!("{base}~~{}", &hex[..12]),
            base,
            snapshot: Some(utc_time(time_ms)),
            layers,
        }
    }

    /// The second since the Unix epoch of the snapshot of the base, or
    /// `None` for a hand-built topology of the tests.
    pub fn snapshot_second(&self) -> Option<u64> {
        snapshot_second(&self.base)
    }

    /// Reads a twin identifier with no scenario. A scenario identifier is
    /// refused until the what-if layers exist.
    pub fn parse(id: &str) -> Result<TwinJson, String> {
        if let Some(t) = id.strip_prefix("builtin.") {
            return TwinJson::builtin(t);
        }
        if id.starts_with(PREFIX) {
            if id.contains('~') {
                return Err(format!("{id:?}: a scenario twin is not available"));
            }
            return snapshot_second(id)
                .map(|s| TwinJson::snapshot(s * 1000))
                .ok_or_else(|| format!("{id:?}: not a UTC second YYYY-MM-DD-HHMMSS"));
        }
        Err(format!(
            "{id:?} is not a twin identifier: builtin.<topology> or snapshot-YYYY-MM-DD-HHMMSS"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-22 14:05:12.345 UTC.
    const TIME: u64 = 1_795_356_312_345;

    #[test]
    fn an_identifier_reads_back_to_its_twin() {
        for t in [
            TwinJson::builtin("leaf-spine").unwrap(),
            TwinJson::snapshot(TIME - 345),
        ] {
            assert_eq!(TwinJson::parse(&t.id), Ok(t.clone()));
            assert!(t.layers.is_empty());
        }
        let t = TwinJson::snapshot(TIME);
        assert_eq!(t.id, "snapshot-2026-11-22-140512");
        assert_eq!(t.snapshot.as_deref(), Some("2026-11-22T14:05:12Z"));
        assert_eq!(t.snapshot_second(), Some(TIME / 1000));
        assert_eq!(TwinJson::builtin("a").unwrap().snapshot_second(), None);
    }

    #[test]
    fn a_name_is_the_utc_second_of_its_time() {
        for (time, name) in [
            (0, "snapshot-1970-01-01-000000"),
            (951_782_400_000, "snapshot-2000-02-29-000000"),
            (1_709_251_199_999, "snapshot-2024-02-29-235959"),
            (4_102_444_800_000, "snapshot-2100-01-01-000000"),
        ] {
            assert_eq!(snapshot_name(time), name);
            assert_eq!(snapshot_second(name), Some(time / 1000), "{name}");
        }
        // Each second of 2 days around a leap day reads back.
        for s in (1_709_164_800..1_709_337_600).step_by(997) {
            assert_eq!(snapshot_second(&snapshot_name(s * 1000)), Some(s));
        }
    }

    #[test]
    fn a_scenario_identifier_holds_the_snapshot_and_the_hash_of_its_layers() {
        let layers = |l: &[&str]| l.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = TwinJson::scenario(TIME, layers(&["link-down r1:eth1", "link-down r2:eth2"]));
        assert_eq!(a.base, "snapshot-2026-11-22-140512");
        assert!(a.id.starts_with("snapshot-2026-11-22-140512~~"), "{}", a.id);
        assert_eq!(a.id.len(), a.base.len() + 2 + 12);
        assert_eq!(a.snapshot.as_deref(), Some("2026-11-22T14:05:12Z"));
        assert_eq!(
            a.layers,
            layers(&["link-down r1:eth1", "link-down r2:eth2"])
        );
        let again = TwinJson::scenario(TIME, layers(&["link-down r1:eth1", "link-down r2:eth2"]));
        assert_eq!(a, again);
        let other = TwinJson::scenario(TIME, layers(&["link-down r2:eth2", "link-down r1:eth1"]));
        assert_ne!(a.id, other.id);
        let joined = TwinJson::scenario(TIME, layers(&["link-down r1:eth1link-down r2:eth2"]));
        assert_ne!(a.id, joined.id);
        // The FNV-1a hash of one line feed.
        assert_eq!(
            TwinJson::scenario(TIME, layers(&[""])).id,
            format!("{}~~af63c74c8601", a.base)
        );
        assert!(TwinJson::parse(&a.id).is_err());
    }

    #[test]
    fn a_name_with_a_separator_or_another_form_is_refused() {
        for bad in ["a.b", "a~b", "Upper", "", "a/b", "a b"] {
            assert!(TwinJson::builtin(bad).is_err(), "{bad:?}");
        }
        for bad in [
            "snap-3",
            "snapshot-2026-11-22-140512~edge~ab12",
            "snapshot-2026-02-30-000000",
            "snapshot-2026-13-01-000000",
            "snapshot-2026-11-22-240000",
            "snapshot-2026-11-22-14051",
            "snapshot-2026-11-22-1405120",
            "snapshot-2026-11-22T140512",
            "snapshot-+026-11-22-140512",
            "snapshot-1969-12-31-235959",
            "other",
            "builtin.a.b",
        ] {
            assert!(TwinJson::parse(bad).is_err(), "{bad:?}");
        }
    }
}
