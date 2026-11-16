use std::collections::BTreeMap;
use std::time::Duration;

use crate::Device;

/// The timing of the collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// The time between 2 collections of a device.
    pub interval: Duration,
    /// The time between 2 forced full collections of a device.
    pub full_interval: Duration,
    /// The wait after the first failure. Each next failure doubles it.
    pub backoff: Duration,
    /// The longest wait after a failure.
    pub max_backoff: Duration,
    /// If true, the forced full collections of the devices are spread over
    /// the full interval. Each device gets a fixed offset from a hash of its
    /// name, so devices that start together are not forced together.
    pub spread: bool,
}

impl Default for Schedule {
    fn default() -> Schedule {
        Schedule {
            interval: Duration::from_secs(60),
            full_interval: Duration::from_secs(900),
            backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(900),
            spread: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    next_due: u64,
    failures: u32,
    next_full: Option<u64>,
}

/// A device that is due, and whether its collection is forced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due {
    pub device: Device,
    pub forced: bool,
}

/// The due time of each device. Times are milliseconds since the Unix
/// epoch.
#[derive(Clone, Debug)]
pub struct Scheduler {
    schedule: Schedule,
    states: BTreeMap<String, State>,
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A fixed hash of the device name (FNV-1a).
fn offset(device: &str) -> u64 {
    device.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl Scheduler {
    pub fn new(schedule: Schedule) -> Scheduler {
        Scheduler {
            schedule,
            states: BTreeMap::new(),
        }
    }

    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// The devices that are due at `now`, sorted by device. A device is due
    /// if its due time is less than half an interval after `now`, so a cycle
    /// that starts a little late does not move the device to the cycle after
    /// it. A new device is due at once, and its first collection is forced.
    pub fn due(&self, now: u64, devices: &[Device]) -> Vec<Due> {
        let at = now.saturating_add(ms(self.schedule.interval) / 2);
        let mut out: Vec<Due> = devices
            .iter()
            .filter_map(|d| {
                let s = self.states.get(&d.id).copied().unwrap_or_default();
                (s.next_due <= at).then(|| Due {
                    device: d.clone(),
                    forced: s.next_full.is_none_or(|t| at >= t),
                })
            })
            .collect();
        out.sort_by(|a, b| a.device.id.cmp(&b.device.id));
        out
    }

    /// Records the result of the collection of a device at `now`.
    pub fn record(&mut self, device: &str, now: u64, forced: bool, failed: bool) {
        let s = self.states.entry(device.to_string()).or_default();
        if failed {
            s.failures = s.failures.saturating_add(1);
            let factor = 1u64 << (s.failures - 1).min(32);
            let wait = ms(self.schedule.backoff)
                .saturating_mul(factor)
                .min(ms(self.schedule.max_backoff));
            s.next_due = now.saturating_add(wait);
        } else {
            s.failures = 0;
            s.next_due = now.saturating_add(ms(self.schedule.interval));
            if forced {
                let full = ms(self.schedule.full_interval);
                let early = if s.next_full.is_none() && self.schedule.spread && full > 0 {
                    offset(device) % full
                } else {
                    0
                };
                s.next_full = Some(now.saturating_add(full - early));
            }
        }
    }

    /// The number of failures in a row of a device.
    pub fn failures(&self, device: &str) -> u32 {
        self.states.get(device).map_or(0, |s| s.failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vendor;

    fn dev(id: &str) -> Device {
        Device {
            id: id.into(),
            vendor: Vendor::Vyos,
            address: "192.0.2.1".into(),
            credential: "lab".into(),
            site: None,
            route: Default::default(),
        }
    }

    const S: u64 = 1000;

    #[test]
    fn a_failure_doubles_the_wait_up_to_the_limit() {
        let mut s = Scheduler::new(Schedule::default());
        let d = [dev("r1")];
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..6 {
            assert_eq!(s.due(now, &d).len(), 1);
            s.record("r1", now, true, true);
            let next = (now..)
                .step_by(60 * S as usize)
                .find(|t| !s.due(*t, &d).is_empty())
                .unwrap();
            waits.push((next - now) / S);
            now = next;
        }
        assert_eq!(waits, vec![60, 120, 240, 480, 900, 900]);
        assert_eq!(s.failures("r1"), 6);
        s.record("r1", now, true, false);
        assert_eq!(s.failures("r1"), 0);
        assert!(s.due(now + 29 * S, &d).is_empty());
        assert_eq!(s.due(now + 60 * S, &d).len(), 1);
    }

    #[test]
    fn a_collection_is_forced_first_and_then_after_the_full_interval() {
        let mut s = Scheduler::new(Schedule {
            spread: false,
            ..Schedule::default()
        });
        let d = [dev("r1")];
        let forced = |s: &Scheduler, t| s.due(t, &d)[0].forced;
        assert!(forced(&s, 0));
        s.record("r1", 0, true, false);
        assert!(!forced(&s, 60 * S));
        assert!(!forced(&s, 840 * S));
        assert!(forced(&s, 900 * S));
        // A forced collection that fails stays forced.
        s.record("r1", 900 * S, true, true);
        assert!(forced(&s, 960 * S));
    }

    #[test]
    fn forced_collections_are_spread_over_the_full_interval() {
        let mut s = Scheduler::new(Schedule::default());
        let devices: Vec<Device> = (0..100).map(|i| dev(&format!("r{i}"))).collect();
        for d in &devices {
            s.record(&d.id, 0, true, false);
        }
        // Each minute, a part of the devices is forced, and each device is
        // forced once in the full interval.
        let mut per_minute = Vec::new();
        for m in 1..=15 {
            let now = m * 60 * S;
            let forced: Vec<String> = s
                .due(now, &devices)
                .into_iter()
                .filter(|d| d.forced)
                .map(|d| d.device.id)
                .collect();
            for d in &devices {
                s.record(&d.id, now, forced.contains(&d.id), false);
            }
            per_minute.push(forced.len());
        }
        assert_eq!(per_minute.iter().sum::<usize>(), 100);
        assert!(per_minute.iter().all(|n| *n < 20), "{per_minute:?}");
    }

    #[test]
    fn a_cycle_that_starts_late_or_early_keeps_the_device_due() {
        let mut s = Scheduler::new(Schedule::default());
        let d = [dev("r1")];
        s.record("r1", 1_000, false, false);
        assert_eq!(s.due(1_000 + 60 * S - 1, &d).len(), 1);
        assert_eq!(s.due(1_000 + 60 * S + 7, &d).len(), 1);
        assert!(s.due(1_000 + 30 * S - 1, &d).is_empty());
    }

    #[test]
    fn due_devices_are_sorted() {
        let s = Scheduler::new(Schedule::default());
        let due = s.due(0, &[dev("b"), dev("a")]);
        let ids: Vec<&str> = due.iter().map(|d| d.device.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
    }
}
