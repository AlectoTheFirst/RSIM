//! Collection cycles of an IOS XE router on the fake transport, with the
//! synthetic answers in `tests/fixtures/iosxe/`.

#![cfg(feature = "iosxe")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rsim_collect::fake::FakeTransport;
use rsim_collect::iosxe::{ARP_VRFS, IosxeSource, arp_vrf_command, sections};
use rsim_collect::*;
use rsim_store::{Keys, SectionStatus, Snapshot, Store};

const T0: u64 = 1_700_000_000_000;

fn fixture(name: &str) -> String {
    let p = format!("{}/tests/fixtures/iosxe/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn router() -> Device {
    Device {
        id: "e1".into(),
        vendor: Vendor::Iosxe,
        address: "192.0.2.10".into(),
        credential: "lab".into(),
        site: None,
        route: Default::default(),
    }
}

/// The fake transport with a log of the commands in the order they are
/// sent, one at a time.
struct Logged {
    fake: Arc<FakeTransport>,
    log: Mutex<Vec<String>>,
    banner: bool,
}

impl Ssh for Logged {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        self.log.lock().unwrap().push(command.to_string());
        self.fake.run(device, command)
    }

    fn banner_each_command(&self, _device: &Device) -> bool {
        self.banner
    }

    fn serial(&self, _device: &Device) -> bool {
        true
    }
}

/// The fixture of each section that has one. The other commands are
/// refused as on a router with no such feature.
fn file(section: &str) -> Option<&'static str> {
    Some(match section {
        "config" => "config.txt",
        "version" => "version.txt",
        "interfaces" => "interfaces.txt",
        "vrfs" => "vrfs.txt",
        "rib" => "rib.txt",
        "rib_global" => "rib_global.txt",
        "arp" => "arp.txt",
        "acls" => "acls.txt",
        "mac_table" => "mac_table.txt",
        "spanning_tree" => "spanning_tree.txt",
        "vlans" => "vlans.txt",
        "hsrp_detail" => "hsrp_detail.txt",
        "vrrp_detail" => "vrrp_detail.txt",
        _ => return None,
    })
}

/// The VRFs of `vrfs.txt` with the fixtures of their ARP tables.
const VRF_ARP: [(&str, &str); 2] = [("BLUE", "arp_blue.txt"), ("RED", "arp_red.txt")];

fn command(section: &str) -> String {
    sections()
        .into_iter()
        .find(|s| s.name == section)
        .unwrap()
        .command
}

fn set(t: &FakeTransport, section: &str, text: &str) {
    t.reply("e1", &command(section), Ok(text.as_bytes().to_vec()));
}

fn set_vrf(t: &FakeTransport, vrf: &str, text: &str) {
    t.reply("e1", &arp_vrf_command(vrf), Ok(text.as_bytes().to_vec()));
}

fn refuse(t: &FakeTransport, command: &str) {
    t.reply(
        "e1",
        command,
        Err(TransportError::Command(
            "% Invalid input detected at '^' marker.".into(),
        )),
    );
}

fn load(t: &FakeTransport) {
    for s in sections() {
        if s.name == ARP_VRFS {
            continue;
        }
        match file(s.name) {
            Some(f) => set(t, s.name, &fixture(f).replace("HOST", "e1")),
            None => refuse(t, &s.command),
        }
    }
    for (vrf, f) in VRF_ARP {
        set_vrf(t, vrf, &fixture(f));
    }
}

struct Env {
    _dir: tempfile::TempDir,
    t: Arc<FakeTransport>,
    ssh: Arc<Logged>,
    c: Collector,
}

fn env_with(banner: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(1)));
    load(&t);
    let ssh = Arc::new(Logged {
        fake: t.clone(),
        log: Mutex::new(Vec::new()),
        banner,
    });
    let store = Store::open(dir.path(), Keys::new([1; 32], [2; 32])).unwrap();
    let c = Collector::new(
        store,
        Box::new(vec![router()]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(IosxeSource::new(ssh.clone())));
    Env {
        _dir: dir,
        t,
        ssh,
        c,
    }
}

fn env() -> Env {
    env_with(false)
}

fn latest(e: &Env) -> Snapshot {
    e.c.store().latest().unwrap().unwrap()
}

fn status(e: &Env, section: &str) -> SectionStatus {
    latest(e).devices["e1"]
        .sections
        .iter()
        .find(|s| s.name == section)
        .unwrap()
        .status
        .clone()
}

fn blob(e: &Env, section: &str) -> String {
    let s = latest(e);
    let entry = s.devices["e1"]
        .sections
        .iter()
        .find(|x| x.name == section)
        .unwrap()
        .clone();
    String::from_utf8(e.c.store().read_blob(entry.blob.as_ref().unwrap()).unwrap()).unwrap()
}

/// The text of the section `arp_vrfs` with the fixtures of the VRFs.
fn arp_vrfs_text() -> String {
    VRF_ARP
        .iter()
        .map(|(vrf, f)| format!("VRF: {vrf}\n{}", fixture(f)))
        .collect()
}

#[tokio::test(start_paused = true)]
async fn the_first_cycle_keeps_each_text_answer() {
    let mut e = env();
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some() && r.failed.is_empty(), "{r:?}");
    for s in [
        "config",
        "version",
        "interfaces",
        "vrfs",
        "rib",
        "rib_global",
        "arp",
        "acls",
        "mac_table",
        "spanning_tree",
        "vlans",
        "hsrp_detail",
        "vrrp_detail",
        ARP_VRFS,
    ] {
        assert_eq!(status(&e, s), SectionStatus::Fresh, "{s}");
    }
    for s in ["lldp", "cdp", "inventory", "hsrp", "vrrp"] {
        assert!(matches!(status(&e, s), SectionStatus::Absent { .. }), "{s}");
    }
    for (s, f) in [
        ("mac_table", "mac_table.txt"),
        ("spanning_tree", "spanning_tree.txt"),
        ("vlans", "vlans.txt"),
        ("hsrp_detail", "hsrp_detail.txt"),
        ("vrrp_detail", "vrrp_detail.txt"),
    ] {
        assert_eq!(blob(&e, s), fixture(f), "{s}");
    }
}

#[tokio::test(start_paused = true)]
async fn the_arp_table_of_each_vrf_follows_its_line_in_name_order() {
    let mut e = env();
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert_eq!(blob(&e, ARP_VRFS), arp_vrfs_text());
    let log = e.ssh.log.lock().unwrap().clone();
    let at = |c: &str| log.iter().position(|x| x == c).unwrap();
    assert!(
        at("show vrf detail") < at("show ip arp vrf BLUE"),
        "{log:#?}"
    );
    assert_eq!(
        log[log.len() - 2..],
        ["show ip arp vrf BLUE", "show ip arp vrf RED"],
        "{log:#?}"
    );
    assert!(!log.iter().any(|c| c.contains('<')), "{log:#?}");
}

#[tokio::test(start_paused = true)]
async fn a_failed_vrf_command_gives_its_failed_line_and_the_others_stay() {
    let mut e = env();
    refuse(&e.t, &arp_vrf_command("BLUE"));
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert_eq!(
        blob(&e, ARP_VRFS),
        format!("VRF: BLUE failed\nVRF: RED\n{}", fixture("arp_red.txt"))
    );
    assert_eq!(status(&e, ARP_VRFS), SectionStatus::Fresh);
}

#[tokio::test(start_paused = true)]
async fn a_rejection_in_the_answer_of_a_vrf_fails_that_vrf() {
    let mut e = env();
    set_vrf(&e.t, "RED", "% Invalid input detected at '^' marker.\n");
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert_eq!(
        blob(&e, ARP_VRFS),
        format!("VRF: BLUE\n{}VRF: RED failed\n", fixture("arp_blue.txt"))
    );
}

#[tokio::test(start_paused = true)]
async fn with_no_vrfs_section_the_arp_of_the_vrfs_is_absent() {
    let mut e = env();
    refuse(&e.t, "show vrf detail");
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert!(matches!(status(&e, "vrfs"), SectionStatus::Absent { .. }));
    assert!(matches!(status(&e, ARP_VRFS), SectionStatus::Absent { .. }));
    let log = e.ssh.log.lock().unwrap().clone();
    assert!(
        !log.iter().any(|c| c.starts_with("show ip arp vrf")),
        "{log:#?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_vrfs_section_makes_the_arp_of_the_vrfs_absent() {
    let mut e = env();
    e.t.reply(
        "e1",
        "show vrf detail",
        Err(TransportError::Command("exit status 1".into())),
    );
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert!(matches!(status(&e, "vrfs"), SectionStatus::Missing { .. }));
    assert!(matches!(status(&e, ARP_VRFS), SectionStatus::Absent { .. }));
}

#[tokio::test(start_paused = true)]
async fn the_banner_of_each_answer_goes_also_from_the_answers_of_the_vrfs() {
    let mut e = env_with(true);
    for s in sections() {
        if let Some(f) = file(s.name) {
            set(&e.t, s.name, &format!("MOTD lab\n{}", fixture(f)));
        }
    }
    for (vrf, f) in VRF_ARP {
        set_vrf(&e.t, vrf, &format!("MOTD lab\n{}", fixture(f)));
    }
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    assert_eq!(blob(&e, ARP_VRFS), arp_vrfs_text());
    assert_eq!(blob(&e, "vlans"), fixture("vlans.txt"));
}

#[tokio::test(start_paused = true)]
async fn the_ages_and_counters_make_no_snapshot_and_a_config_change_makes_one() {
    let mut e = env();
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let swap = |f: &str, a: &str, b: &str| fixture(f).replace("HOST", "e1").replace(a, b);
    let later = |f: &str| {
        let mut t = swap(f, "09:58:12 UTC", "10:00:59 UTC");
        for (a, b) in [
            ("1234 bytes", "1240 bytes"),
            ("3 minutes", "4 minutes"),
            (
                "Internet  198.51.100.254         12",
                "Internet  198.51.100.254         13",
            ),
            ("(5 matches)", "(9 matches)"),
            ("(1234 matches)", "(1300 matches)"),
            ("3w2d", "3w3d"),
            ("2 days, 4 hours, 1 minute", "2 days, 4 hours, 2 minutes"),
            ("123456 packets input", "123999 packets input"),
            ("3 packets/sec", "7 packets/sec"),
            ("Received 12 broadcast", "Received 19 broadcast"),
            ("Output 2 broadcast", "Output 5 broadcast"),
            ("Last input 00:00:00", "Last input 00:00:01"),
        ] {
            t = t.replace(a, b);
        }
        t
    };
    for (s, f) in [
        ("config", "config.txt"),
        ("version", "version.txt"),
        ("rib", "rib.txt"),
        ("rib_global", "rib_global.txt"),
        ("interfaces", "interfaces.txt"),
        ("arp", "arp.txt"),
        ("acls", "acls.txt"),
    ] {
        set(&e.t, s, &later(f));
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);

    set(
        &e.t,
        "config",
        &swap("config.txt", "description to-core", "description to-core-2"),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(e.c.run_cycle().await.unwrap().snapshot.is_some());
    set(
        &e.t,
        "rib",
        &swap("rib.txt", "via 203.0.113.9", "via 203.0.113.8"),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(e.c.run_cycle().await.unwrap().snapshot.is_some());
}

#[tokio::test(start_paused = true)]
async fn the_timers_of_the_new_sections_make_no_snapshot() {
    let mut e = env();
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let swap = |f: &str, pairs: &[(&str, &str)]| {
        let mut t = fixture(f);
        for (a, b) in pairs {
            assert!(t.contains(a), "{f}: {a}");
            t = t.replace(a, b);
        }
        t
    };
    set(
        &e.t,
        "hsrp_detail",
        &swap(
            "hsrp_detail.txt",
            &[
                (
                    "2 state changes, last state change 1w2d",
                    "3 state changes, last state change 1w3d",
                ),
                (
                    "Next hello sent in 1.264 secs",
                    "Next hello sent in 0.512 secs",
                ),
                ("(expires in 9.808 sec)", "(expires in 7.120 sec)"),
            ],
        ),
    );
    set(
        &e.t,
        "vrrp_detail",
        &swap(
            "vrrp_detail.txt",
            &[(
                "Master Down interval is 3.570 sec",
                "Master Down interval is 3.609 sec",
            )],
        ),
    );
    set(
        &e.t,
        "spanning_tree",
        &format!(
            "{}  Number of topology changes 4 last change occurred 00:02:01 ago\n          from Port-channel1\n",
            fixture("spanning_tree.txt")
        ),
    );
    set_vrf(
        &e.t,
        "RED",
        &swap(
            "arp_red.txt",
            &[(
                "Internet  203.0.113.2            21",
                "Internet  203.0.113.2            22",
            )],
        ),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);
}

#[tokio::test(start_paused = true)]
async fn a_change_of_each_new_section_makes_a_snapshot() {
    let mut e = env();
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let changes: [(&str, &str, &str, &str); 5] = [
        ("mac_table", "mac_table.txt", "Gi1/0/2", "Gi1/0/4"),
        ("spanning_tree", "spanning_tree.txt", "Root FWD", "Altn BLK"),
        ("vlans", "vlans.txt", "VOICE", "PHONES"),
        (
            "hsrp_detail",
            "hsrp_detail.txt",
            "Active router is local",
            "Active router is 192.0.2.3, priority 120 (expires in 9.808 sec)",
        ),
        (
            "vrrp_detail",
            "vrrp_detail.txt",
            "Master Router is 198.51.100.2 (local)",
            "Master Router is 198.51.100.3",
        ),
    ];
    for (s, f, a, b) in changes {
        set(&e.t, s, &fixture(f).replacen(a, b, 1));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(e.c.run_cycle().await.unwrap().snapshot.is_some(), "{s}");
    }
    set_vrf(
        &e.t,
        "BLUE",
        &fixture("arp_blue.txt").replace("0000.5e00.5311", "0000.5e00.5312"),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(e.c.run_cycle().await.unwrap().snapshot.is_some());
    refuse(&e.t, &arp_vrf_command("BLUE"));
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(e.c.run_cycle().await.unwrap().snapshot.is_some());
}

#[tokio::test(start_paused = true)]
async fn an_unreachable_router_fails_and_its_arp_of_the_vrfs_keeps_its_blob() {
    let mut e = env();
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let before = blob(&e, ARP_VRFS);
    e.t.clear("e1");
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.failed, ["e1"], "{r:?}");
    assert!(r.changed.is_empty(), "{r:?}");
    assert!(
        matches!(status(&e, ARP_VRFS), SectionStatus::Old { .. }),
        "{:?}",
        status(&e, ARP_VRFS)
    );
    assert_eq!(blob(&e, ARP_VRFS), before);
}

#[tokio::test(start_paused = true)]
async fn a_lost_connection_after_the_vrfs_keeps_the_blob_of_the_arp_of_the_vrfs() {
    let mut e = env();
    e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let before = blob(&e, ARP_VRFS);
    for (vrf, _) in VRF_ARP {
        e.t.reply(
            "e1",
            &arp_vrf_command(vrf),
            Err(TransportError::Connect("closed".into())),
        );
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    e.c.run_cycle().await.unwrap();
    assert!(
        matches!(status(&e, ARP_VRFS), SectionStatus::Old { .. }),
        "{:?}",
        status(&e, ARP_VRFS)
    );
    assert_eq!(blob(&e, ARP_VRFS), before);
}
