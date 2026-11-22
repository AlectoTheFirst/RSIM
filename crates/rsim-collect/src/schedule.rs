use std::collections::BTreeMap;
use std::time::Duration;

use crate::Device;

/// The timing of the collection. The interval of each device is in its
/// [`Device`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// The time between 2 forced full collections of a device. A device
    /// with an interval of this time or more gets a full collection each
    /// time.
    pub full_interval: Duration,
    /// The wait after the first failure. Each next failure doubles it.
    pub backoff: Duration,
    /// The longest wait after a failure.
    pub max_backoff: Duration,
    /// If true, the forced full collections of the devices are spread over
    /// the full interval. Each device gets a fixed offset from a hash of its
    /// name, so devices that start together are not forced together.
    pub spread: bool,
    /// A device is due when its due time is at most this time after the
    /// time of the cycle.
    pub slack: Duration,
}

impl Default for Schedule {
    fn default() -> Schedule {
        Schedule {
            full_interval: Duration::from_secs(900),
            backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(900),
            spread: true,
            slack: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    /// The time of the last collection with no failure.
    last: Option<u64>,
    /// The time of the next try after a failure.
    retry: Option<u64>,
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

    /// The due time of a device: after a failure the time of the next try,
    /// else the last collection plus the interval of the device. A new
    /// device is due at 0.
    pub fn due_at(&self, device: &Device) -> u64 {
        let s = self.states.get(&device.id).copied().unwrap_or_default();
        match (s.retry, s.last) {
            (Some(t), _) => t,
            (None, Some(t)) => t.saturating_add(ms(device.interval)),
            (None, None) => 0,
        }
    }

    /// The earliest due time of the devices, or `None` with no device.
    pub fn next_due(&self, devices: &[Device]) -> Option<u64> {
        devices.iter().map(|d| self.due_at(d)).min()
    }

    /// The devices that are due at `now`, sorted by device. A device is due
    /// if its due time is at most the slack after `now`. The first
    /// collection of a new device is forced, and so is each collection of a
    /// device whose interval is the full interval or more.
    pub fn due(&self, now: u64, devices: &[Device]) -> Vec<Due> {
        let at = now.saturating_add(ms(self.schedule.slack));
        let full = self.schedule.full_interval;
        let mut out: Vec<Due> = devices
            .iter()
            .filter(|d| self.due_at(d) <= at)
            .map(|d| {
                let s = self.states.get(&d.id).copied().unwrap_or_default();
                Due {
                    device: d.clone(),
                    forced: d.interval >= full || s.next_full.is_none_or(|t| at >= t),
                }
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
            s.retry = Some(now.saturating_add(wait));
        } else {
            s.failures = 0;
            s.retry = None;
            s.last = Some(now);
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

    /// Drops the times of a device, so the device is new to the scheduler.
    pub fn forget(&mut self, device: &str) {
        self.states.remove(device);
    }

    /// The number of failures in a row of a device.
    pub fn failures(&self, device: &str) -> u32 {
        self.states.get(device).map_or(0, |s| s.failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_INTERVAL, Vendor};

    fn every(id: &str, interval: u64) -> Device {
        Device {
            id: id.into(),
            vendor: Vendor::Vyos,
            address: "192.0.2.1".into(),
            credential: "lab".into(),
            site: None,
            capture_bgp: Default::default(),
            route: Default::default(),
            interval: Duration::from_secs(interval),
        }
    }

    fn dev(id: &str) -> Device {
        every(id, DEFAULT_INTERVAL.as_secs())
    }

    const S: u64 = 1000;

    fn unspread() -> Schedule {
        Schedule {
            spread: false,
            ..Schedule::default()
        }
    }

    /// Runs the cycles of a collector that wakes at the earliest due time,
    /// up to `end`, and gives the times of the cycles of each device and
    /// whether each was forced.
    fn run(s: &mut Scheduler, devices: &[Device], end: u64) -> BTreeMap<String, Vec<(u64, bool)>> {
        let mut out: BTreeMap<String, Vec<(u64, bool)>> = BTreeMap::new();
        let mut now = 0;
        while now <= end {
            for d in s.due(now, devices) {
                s.record(&d.device.id, now, d.forced, false);
                out.entry(d.device.id)
                    .or_default()
                    .push((now / S, d.forced));
            }
            now = s.next_due(devices).unwrap();
        }
        out
    }

    #[test]
    fn a_failure_doubles_the_wait_up_to_the_limit() {
        let mut s = Scheduler::new(Schedule::default());
        let d = [dev("r1")];
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..6 {
            assert_eq!(s.due(now, &d).len(), 1);
            s.record("r1", now, true, true);
            let next = s.next_due(&d).unwrap();
            waits.push((next - now) / S);
            now = next;
        }
        assert_eq!(waits, vec![60, 120, 240, 480, 900, 900]);
        assert_eq!(s.failures("r1"), 6);
        s.record("r1", now, true, false);
        assert_eq!(s.failures("r1"), 0);
        assert!(s.due(now + 58 * S, &d).is_empty());
        assert_eq!(s.due(now + 60 * S, &d).len(), 1);
    }

    #[test]
    fn a_collection_is_forced_first_and_then_after_the_full_interval() {
        let mut s = Scheduler::new(unspread());
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
    fn a_device_is_due_from_the_slack_before_its_due_time() {
        let mut s = Scheduler::new(Schedule::default());
        let d = [dev("r1")];
        s.record("r1", 1_000, false, false);
        assert_eq!(s.next_due(&d), Some(61_000));
        assert!(s.due(61_000 - 1_001, &d).is_empty());
        assert_eq!(s.due(61_000 - 1_000, &d).len(), 1);
        assert_eq!(s.due(61_000 + 7, &d).len(), 1);
    }

    #[test]
    fn due_devices_are_sorted() {
        let s = Scheduler::new(Schedule::default());
        let due = s.due(0, &[dev("b"), dev("a")]);
        let ids: Vec<&str> = due.iter().map(|d| d.device.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn each_device_keeps_its_own_interval() {
        let mut s = Scheduler::new(unspread());
        let devices = [every("a", 60), every("b", 90), every("c", 3_600)];
        let runs = run(&mut s, &devices, 3_600 * S);
        let times = |id: &str| -> Vec<u64> { runs[id].iter().map(|(t, _)| *t).collect() };
        assert_eq!(times("a"), (0..=60).map(|m| m * 60).collect::<Vec<_>>());
        assert_eq!(times("b"), (0..=40).map(|m| m * 90).collect::<Vec<_>>());
        assert_eq!(times("c"), [0, 3_600]);
    }

    #[test]
    fn a_changed_interval_applies_from_the_last_collection() {
        let mut s = Scheduler::new(unspread());
        s.record("r1", 0, true, false);
        assert_eq!(s.next_due(&[every("r1", 60)]), Some(60 * S));
        assert_eq!(s.next_due(&[every("r1", 600)]), Some(600 * S));
        assert!(s.due(60 * S, &[every("r1", 600)]).is_empty());
        assert_eq!(s.next_due(&[]), None);
    }

    #[test]
    fn the_full_collection_comes_at_the_first_collection_after_the_full_interval() {
        let mut s = Scheduler::new(unspread());
        let runs = run(&mut s, &[every("a", 600), every("b", 900)], 3_600 * S);
        assert_eq!(
            runs["a"],
            [
                (0, true),
                (600, false),
                (1_200, true),
                (1_800, false),
                (2_400, true),
                (3_000, false),
                (3_600, true)
            ]
        );
        // An interval of the full interval or more is a full collection
        // each time.
        assert!(runs["b"].iter().all(|(_, forced)| *forced), "{runs:?}");
        let mut s = Scheduler::new(Schedule::default());
        let runs = run(&mut s, &[every("c", 86_400)], 2 * 86_400 * S);
        assert_eq!(runs["c"], [(0, true), (86_400, true), (172_800, true)]);
    }
}
