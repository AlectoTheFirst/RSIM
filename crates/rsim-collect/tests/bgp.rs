//! The BGP sections of the routers on the fake transport, with the
//! synthetic answers in `tests/fixtures/<vendor>/bgp_*`.

#![cfg(all(
    feature = "vyos",
    feature = "nxos",
    feature = "iosxr",
    feature = "iosxe"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rsim_collect::bgp::{self, CaptureBgp};
use rsim_collect::fake::FakeTransport;
use rsim_collect::iosxe::IosxeSource;
use rsim_collect::iosxr::IosxrSource;
use rsim_collect::nxos::{BGP_SESSIONS_DEFAULT, NxosSource};
use rsim_collect::vyos::VyosSource;
use rsim_collect::*;
use rsim_store::{SectionEntry, SectionStatus, Store};

#[path = "support/keys.rs"]
mod keys;

const T0: u64 = 1_700_000_000_000;

fn fixture(path: &str) -> String {
    let p = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn device(vendor: Vendor, capture_bgp: CaptureBgp) -> Device {
    Device {
        id: "r1".into(),
        vendor,
        address: "192.0.2.10".into(),
        credential: "lab".into(),
        site: None,
        capture_bgp,
        route: Default::default(),
        interval: DEFAULT_INTERVAL,
    }
}

/// The fake transport with a log of the commands in the order they are
/// sent, one at a time. A command with no reply is refused.
struct Logged {
    fake: FakeTransport,
    log: Mutex<Vec<String>>,
}

impl Ssh for Logged {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        self.log.lock().unwrap().push(command.to_string());
        Box::pin(async move {
            match self.fake.run(device, command).await {
                Err(TransportError::Connect(e)) if e == "no reply is recorded" => {
                    Err(TransportError::Command("refused".into()))
                }
                r => r,
            }
        })
    }

    fn serial(&self, _device: &Device) -> bool {
        true
    }
}

impl Logged {
    fn reply(&self, command: &str, text: &str) {
        self.fake.reply("r1", command, Ok(text.as_bytes().to_vec()));
    }

    fn fail(&self, command: &str, error: TransportError) {
        self.fake.reply("r1", command, Err(error));
    }

    fn sent(&self, command: &str) -> bool {
        self.log.lock().unwrap().iter().any(|c| c == command)
    }
}

struct Env {
    dir: tempfile::TempDir,
    t: Arc<Logged>,
    c: Collector,
}

/// A transport with an answer to the section `version` of `base`, so that
/// a cycle with no BGP section stores the device.
fn transport(base: &[SectionSpec]) -> Arc<Logged> {
    let t = Arc::new(Logged {
        fake: FakeTransport::new(Duration::from_millis(1)),
        log: Mutex::new(Vec::new()),
    });
    let version = base.iter().find(|s| s.name == "version").unwrap();
    let answer = match version.format {
        rsim_store::Format::Json => "{}",
        rsim_store::Format::Text => "version 1\n",
    };
    t.reply(&version.command, answer);
    t
}

fn collector(
    dir: &std::path::Path,
    vendor: Vendor,
    capture: CaptureBgp,
    source: Arc<dyn Source>,
) -> Collector {
    let store = Store::open(dir, keys::keys()).unwrap();
    Collector::new(
        store,
        Box::new(vec![device(vendor, capture)]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(source)
}

fn source(vendor: Vendor, t: &Arc<Logged>) -> Arc<dyn Source> {
    match vendor {
        Vendor::Vyos => Arc::new(VyosSource::new(t.clone())),
        Vendor::Nxos => Arc::new(NxosSource::new(t.clone())),
        Vendor::Iosxr => Arc::new(IosxrSource::new(t.clone())),
        Vendor::Iosxe => Arc::new(IosxeSource::new(t.clone())),
        Vendor::Unifi => unreachable!("UniFi has no BGP"),
    }
}

fn base(vendor: Vendor) -> Vec<SectionSpec> {
    match vendor {
        Vendor::Vyos => rsim_collect::vyos::sections_with(CaptureBgp::Off),
        Vendor::Nxos => rsim_collect::nxos::sections_with(false, CaptureBgp::Off),
        Vendor::Iosxr => rsim_collect::iosxr::sections_with(CaptureBgp::Off),
        Vendor::Iosxe => rsim_collect::iosxe::sections_with(CaptureBgp::Off),
        Vendor::Unifi => unreachable!("UniFi has no BGP"),
    }
}

fn env(vendor: Vendor, capture: CaptureBgp) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = transport(&base(vendor));
    let c = collector(dir.path(), vendor, capture, source(vendor, &t));
    Env { dir, t, c }
}

fn entry(e: &Env, section: &str) -> Option<SectionEntry> {
    e.c.store().latest().unwrap().unwrap().devices["r1"]
        .section(section)
        .cloned()
}

fn bytes(e: &Env, section: &str) -> String {
    let blob = entry(e, section).unwrap().blob.unwrap();
    String::from_utf8(e.c.store().read_blob(&blob).unwrap()).unwrap()
}

fn absent(e: &Env, section: &str) -> bool {
    matches!(
        entry(e, section).unwrap().status,
        SectionStatus::Absent { .. }
    )
}

/// The change hash of a section of a vendor over an answer.
fn hash(vendor: Vendor, capture: CaptureBgp, section: &str, answer: &str) -> rsim_store::Hash {
    let specs = match vendor {
        Vendor::Vyos => rsim_collect::vyos::sections_with(capture),
        Vendor::Nxos => rsim_collect::nxos::sections_with(false, capture),
        Vendor::Iosxr => rsim_collect::iosxr::sections_with(capture),
        Vendor::Iosxe => rsim_collect::iosxe::sections_with(capture),
        Vendor::Unifi => unreachable!(),
    };
    let spec = specs.into_iter().find(|s| s.name == section).unwrap();
    let keys = keys::keys();
    rsim_store::change_hash_kept(
        &keys,
        spec.format,
        answer.as_bytes(),
        spec.volatile,
        spec.keep,
    )
    .unwrap()
}

/// Checks that each counter edit keeps the change hash and that each state
/// edit changes it.
fn check_hash(
    vendor: Vendor,
    section: &str,
    answer: &str,
    counters: &[(&str, &str)],
    states: &[(&str, &str)],
) {
    let h = |a: &str| hash(vendor, CaptureBgp::All, section, a);
    let first = h(answer);
    let mut later = answer.to_string();
    for (a, b) in counters {
        assert!(later.contains(a), "{vendor} {a}");
        later = later.replace(a, b);
    }
    assert_eq!(first, h(&later), "{vendor}: a counter changed the hash");
    for (a, b) in states {
        assert!(answer.contains(a), "{vendor} {a}");
        assert_ne!(first, h(&answer.replace(a, b)), "{vendor}: {a} -> {b}");
    }
}

const IOSXR_CONFIG: &str = "Tue Nov 17 10:00:00.000 UTC\nhostname r1\nvrf RED\n!\nvrf BLUE\n!\n\
    router bgp 64500\n neighbor 192.0.2.2\n  remote-as 64501\n !\n vrf BLUE\n  rd 64500:2\n !\n \
    vrf RED\n  rd 64500:1\n  neighbor 203.0.113.2\n   remote-as 65551\n  !\n !\n!\nend\n";

const IOSXE_CONFIG: &str = "hostname r1\n!\nvrf definition RED\n rd 64500:1\n!\n\
    router bgp 64500\n bgp listen range 203.0.113.0/24 peer-group DYN\n \
    neighbor 192.0.2.2 remote-as 64501\n !\n address-family ipv4 vrf RED\n  \
    neighbor 203.0.113.2 remote-as 65551\n  neighbor 203.0.113.2 activate\n \
    exit-address-family\n!\nend\n";

#[tokio::test(start_paused = true)]
async fn vyos_stores_the_sessions_and_a_router_with_no_bgp_has_none() {
    let mut e = env(Vendor::Vyos, CaptureBgp::Sessions);
    let summary = fixture("vyos/bgp_sessions.json");
    e.t.reply(rsim_collect::vyos::BGP_SESSIONS_COMMAND, &summary);
    e.c.run_cycle().await.unwrap();
    assert_eq!(
        entry(&e, bgp::SESSIONS).unwrap().status,
        SectionStatus::Fresh
    );
    assert_eq!(bytes(&e, bgp::SESSIONS), summary);
    assert!(entry(&e, bgp::ROUTES).is_none());

    e.t.reply(
        rsim_collect::vyos::BGP_SESSIONS_COMMAND,
        "% BGP instance not found\n",
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    e.c.run_cycle().await.unwrap();
    assert!(absent(&e, bgp::SESSIONS));
}

#[test]
fn a_state_change_alters_the_hash_of_the_sessions_and_a_counter_change_does_not() {
    check_hash(
        Vendor::Vyos,
        bgp::SESSIONS,
        &fixture("vyos/bgp_sessions.json"),
        &[
            ("\"msgRcvd\": 1201", "\"msgRcvd\": 1301"),
            (
                "\"peerUptime\": \"20:01:02\"",
                "\"peerUptime\": \"21:01:02\"",
            ),
            (
                "\"peerUptimeMsec\": 72062000",
                "\"peerUptimeMsec\": 75662000",
            ),
            ("\"pfxRcd\": 3", "\"pfxRcd\": 4"),
            ("\"tableVersion\": 12", "\"tableVersion\": 13"),
        ],
        &[
            ("\"state\": \"Established\"", "\"state\": \"Idle\""),
            ("\"remoteAs\": 64502", "\"remoteAs\": 64503"),
            ("\"198.51.100.2\"", "\"198.51.100.3\""),
        ],
    );
    check_hash(
        Vendor::Nxos,
        bgp::SESSIONS,
        &fixture("nxos/bgp_sessions.json"),
        &[
            ("\"lastflap\": \"PT20H1M2S\"", "\"lastflap\": \"PT21H1M2S\""),
            ("\"lastread\": \"PT10S\"", "\"lastread\": \"PT11S\""),
            ("\"remoteport\": \"51234\"", "\"remoteport\": \"51299\""),
            (
                "\"connectionsdropped\": \"2\"",
                "\"connectionsdropped\": \"3\"",
            ),
            (
                "\"notificationssent\": \"1\"",
                "\"notificationssent\": \"2\"",
            ),
        ],
        &[
            ("\"state\": \"Idle\"", "\"state\": \"Active\""),
            ("\"remoteas\": \"65551\"", "\"remoteas\": \"65550\""),
            ("\"vrf-name-out\": \"RED\"", "\"vrf-name-out\": \"BLUE\""),
        ],
    );
    let xr_counters: &[(&str, &str)] = &[
        ("10:00:00.000", "10:01:00.000"),
        ("RD version: 12", "RD version: 13"),
        ("table version 12", "table version 13"),
        (
            "Speaker              12         12",
            "Speaker              13         13",
        ),
        ("1201    1199       12", "1261    1259       13"),
        ("1d02h             3", "1d03h             4"),
        ("00:10:02", "00:11:02"),
    ];
    check_hash(
        Vendor::Iosxr,
        bgp::SESSIONS,
        &fixture("iosxr/bgp_sessions.txt"),
        xr_counters,
        &[
            ("1d02h             3", "1d02h             Idle"),
            ("never    Idle", "never    Active"),
            ("Idle (Admin)", "Idle"),
            ("198.51.100.2 ", "198.51.100.3 "),
        ],
    );
    check_hash(
        Vendor::Iosxe,
        bgp::SESSIONS,
        &fixture("iosxe/bgp_sessions.txt"),
        &[
            (
                "table version is 12, main routing table version 12",
                "table version is 15, main routing table version 15",
            ),
            (
                "5 network entries using 1240",
                "6 network entries using 1488",
            ),
            ("BGP activity 7/2", "BGP activity 8/2"),
            (
                "10:01:02 Nov 17 2026 (1d02h ago)",
                "10:01:02 Nov 17 2026 (1d03h ago)",
            ),
            ("1201    1199       12", "1261    1259       15"),
            ("1d02h           3", "1d03h           4"),
            ("00:20:00        1", "00:21:00        2"),
        ],
        &[
            ("1d02h           3", "1d02h           Idle"),
            ("never    Idle", "never    Active"),
            ("*203.0.113.7", "*203.0.113.8"),
        ],
    );
}

#[tokio::test(start_paused = true)]
async fn nxos_reads_the_global_table_when_the_switch_refuses_the_form_of_all_vrfs() {
    let mut e = env(Vendor::Nxos, CaptureBgp::Sessions);
    let summary = fixture("nxos/bgp_sessions.json");
    e.t.reply(rsim_collect::nxos::BGP_SESSIONS_COMMAND, &summary);
    e.c.run_cycle().await.unwrap();
    assert_eq!(
        entry(&e, bgp::SESSIONS).unwrap().status,
        SectionStatus::Fresh
    );
    assert!(bytes(&e, bgp::SESSIONS).contains("\"ROW_neighbor\":[{"));
    assert!(absent(&e, BGP_SESSIONS_DEFAULT));
    assert!(!e.t.sent(rsim_collect::nxos::BGP_SESSIONS_DEFAULT_COMMAND));

    let mut e = env(Vendor::Nxos, CaptureBgp::Sessions);
    e.t.reply(
        rsim_collect::nxos::BGP_SESSIONS_COMMAND,
        "% Invalid command at '^' marker.\n",
    );
    e.t.reply(
        rsim_collect::nxos::BGP_SESSIONS_DEFAULT_COMMAND,
        &summary.replace("\"RED\"", "\"default\""),
    );
    e.c.run_cycle().await.unwrap();
    assert!(absent(&e, bgp::SESSIONS));
    assert_eq!(
        entry(&e, BGP_SESSIONS_DEFAULT).unwrap().status,
        SectionStatus::Fresh
    );

    // A switch with no BGP refuses both forms.
    let mut e = env(Vendor::Nxos, CaptureBgp::Sessions);
    for c in [
        rsim_collect::nxos::BGP_SESSIONS_COMMAND,
        rsim_collect::nxos::BGP_SESSIONS_DEFAULT_COMMAND,
    ] {
        e.t.reply(c, "% Invalid command at '^' marker.\n");
    }
    e.c.run_cycle().await.unwrap();
    assert!(absent(&e, bgp::SESSIONS) && absent(&e, BGP_SESSIONS_DEFAULT));
}

#[tokio::test(start_paused = true)]
async fn nxos_with_all_reads_the_tables_of_each_ipv4_neighbour_with_native_json() {
    let dir = tempfile::tempdir().unwrap();
    let t = transport(&base(Vendor::Nxos));
    t.reply(
        "show bgp sessions vrf all | json native",
        &fixture("nxos/bgp_sessions.json"),
    );
    t.reply(
        "show bgp vrf RED ipv4 unicast neighbors 203.0.113.2 routes | json native",
        r#"{"TABLE_vrf":{"ROW_vrf":{"vrf-name-out":"RED","TABLE_afi":{"ROW_afi":null}}}}"#,
    );
    t.reply(
        "show bgp vrf all neighbors | json native",
        &fixture("nxos/bgp_neighbors.json"),
    );
    let s = NxosSource::new(t.clone()).with_native_json("r1");
    let mut c = collector(dir.path(), Vendor::Nxos, CaptureBgp::All, Arc::new(s));
    c.run_cycle().await.unwrap();
    let log = t.log.lock().unwrap().clone();
    let routes: Vec<&String> = log
        .iter()
        .filter(|c| c.contains("unicast neighbors"))
        .collect();
    assert_eq!(routes.len(), 3 * 3, "{routes:?}");
    assert!(routes.iter().all(|c| c.ends_with("| json native")));
    assert!(!log.iter().any(|c| c.contains("2001:db8::2")));
    assert!(t.sent("show bgp ipv4 unicast neighbors 198.51.100.2 received-routes | json native"));
    let snap = c.store().latest().unwrap().unwrap();
    let e = snap.devices["r1"].section(bgp::ROUTES).unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&c.store().read_blob(&e.blob.unwrap()).unwrap()).unwrap();
    assert_eq!(
        v["RED"]["203.0.113.2"]["routes"]["answer"]["TABLE_vrf"]["ROW_vrf"][0]["TABLE_afi"]["ROW_afi"],
        serde_json::json!([])
    );
    let n = snap.devices["r1"].section(bgp::NEIGHBORS).unwrap();
    assert_eq!(n.status, SectionStatus::Fresh);
    let stored: serde_json::Value =
        serde_json::from_slice(&c.store().read_blob(&n.blob.unwrap()).unwrap()).unwrap();
    let fixed: serde_json::Value =
        serde_json::from_str(&fixture("nxos/bgp_neighbors.json")).unwrap();
    assert_eq!(stored, fixed);
}

#[tokio::test(start_paused = true)]
async fn iosxr_reads_the_summary_of_each_vrf_of_the_bgp_block() {
    let mut e = env(Vendor::Iosxr, CaptureBgp::Sessions);
    e.t.reply("show running-config", IOSXR_CONFIG);
    e.t.reply("show bgp summary", &fixture("iosxr/bgp_sessions.txt"));
    let red = fixture("iosxr/bgp_vrf_red.txt");
    e.t.reply("show bgp vrf RED ipv4 unicast summary", &red);
    e.t.fail(
        "show bgp vrf BLUE ipv4 unicast summary",
        TransportError::Command("rejected".into()),
    );
    e.c.run_cycle().await.unwrap();
    assert_eq!(
        entry(&e, bgp::SESSIONS).unwrap().status,
        SectionStatus::Fresh
    );
    let vrfs = bytes(&e, rsim_collect::iosxr::BGP_VRF_SESSIONS);
    assert_eq!(vrfs, format!("VRF: BLUE failed\nVRF: RED\n{red}"));
    let log = e.t.log.lock().unwrap().clone();
    let at = |c: &str| log.iter().position(|x| x == c).unwrap();
    assert!(at("show running-config") < at("show bgp vrf BLUE ipv4 unicast summary"));
    assert!(
        at("show bgp vrf BLUE ipv4 unicast summary") < at("show bgp vrf RED ipv4 unicast summary")
    );
    assert!(entry(&e, bgp::NEIGHBORS).is_none());
}

#[tokio::test(start_paused = true)]
async fn iosxe_with_all_reads_the_tables_of_each_neighbour_of_the_summaries() {
    let mut e = env(Vendor::Iosxe, CaptureBgp::All);
    e.t.reply("show running-config", IOSXE_CONFIG);
    e.t.reply("show ip bgp summary", &fixture("iosxe/bgp_sessions.txt"));
    e.t.reply(
        "show ip bgp vpnv4 vrf RED summary",
        &fixture("iosxe/bgp_vrf_red.txt"),
    );
    let neighbors = fixture("iosxe/bgp_neighbors.txt");
    e.t.reply("show bgp all neighbors", &neighbors);
    let table = "BGP table version is 12, local router ID is 192.0.2.1\n\
                 \x20    Network          Next Hop            Metric LocPrf Weight Path\n\
                 \x20*>   198.51.100.0/24  192.0.2.2                0             0 64501 i\n";
    e.t.reply("show ip bgp neighbors 192.0.2.2 routes", table);
    e.t.reply(
        "show ip bgp neighbors 192.0.2.2 received-routes",
        "% Inbound soft reconfiguration not enabled on 192.0.2.2\n",
    );
    e.t.reply(
        "show ip bgp vpnv4 vrf RED neighbors 203.0.113.2 advertised-routes",
        table,
    );
    e.c.run_cycle().await.unwrap();

    let peers = [
        ("", "192.0.2.2"),
        ("", "198.51.100.2"),
        ("", "198.51.100.6"),
        ("", "203.0.113.7"),
        ("vpnv4 vrf RED ", "203.0.113.2"),
    ];
    for (scope, peer) in peers {
        for d in bgp::DIRECTIONS {
            let c = format!("show ip bgp {scope}neighbors {peer} {d}");
            assert!(e.t.sent(&c), "{c}");
        }
    }
    let log = e.t.log.lock().unwrap().clone();
    assert!(
        !log.iter().any(|c| c.contains("203.0.113.0")),
        "no range is a neighbour"
    );
    assert!(
        !log.iter()
            .any(|c| c.contains("neighbors 203.0.113.2") && !c.contains("vrf RED"))
    );

    let routes = bytes(&e, bgp::ROUTES);
    assert!(
        routes.starts_with("NEIGHBOR: RED 203.0.113.2 received-routes failed\n"),
        "{routes}"
    );
    assert!(routes.contains(&format!(
        "NEIGHBOR: RED 203.0.113.2 advertised-routes\n{table}"
    )));
    assert!(
        routes.contains(
            "NEIGHBOR: default 192.0.2.2 received-routes\n% Inbound soft reconfiguration"
        )
    );
    assert!(routes.contains(&format!("NEIGHBOR: default 192.0.2.2 routes\n{table}")));
    assert_eq!(
        entry(&e, bgp::NEIGHBORS).unwrap().status,
        SectionStatus::Fresh
    );
    assert_eq!(bytes(&e, bgp::NEIGHBORS), neighbors);
}

#[tokio::test(start_paused = true)]
async fn iosxr_with_all_reads_the_neighbour_detail_and_the_tables() {
    let mut e = env(Vendor::Iosxr, CaptureBgp::All);
    e.t.reply("show running-config", IOSXR_CONFIG);
    e.t.reply("show bgp summary", &fixture("iosxr/bgp_sessions.txt"));
    e.t.reply(
        "show bgp vrf RED ipv4 unicast summary",
        &fixture("iosxr/bgp_vrf_red.txt"),
    );
    let neighbors = fixture("iosxr/bgp_neighbors.txt");
    e.t.reply("show bgp neighbors", &neighbors);
    e.t.reply(
        "show bgp vrf all neighbors",
        &neighbors.replace("192.0.2.2", "203.0.113.2"),
    );
    let table = "Tue Nov 17 10:00:03.000 UTC\nBGP router identifier 192.0.2.1, local AS number 64500\n\
                 Status codes: s suppressed, d damped, h history, * valid, > best\n\
                 \x20  Network            Next Hop            Metric LocPrf Weight Path\n\
                 *> 198.51.100.0/24    192.0.2.2                0             0 64501 i\n";
    e.t.reply("show bgp neighbors 192.0.2.2 received routes", table);
    e.t.reply(
        "show bgp vrf RED ipv4 unicast neighbors 203.0.113.2 advertised-routes",
        table,
    );
    e.c.run_cycle().await.unwrap();
    assert_eq!(bytes(&e, bgp::NEIGHBORS), neighbors);
    assert_eq!(
        entry(&e, rsim_collect::iosxr::BGP_VRF_NEIGHBORS)
            .unwrap()
            .status,
        SectionStatus::Fresh
    );
    for peer in ["192.0.2.2", "198.51.100.2", "198.51.100.6"] {
        for d in ["received routes", "routes", "advertised-routes"] {
            assert!(
                e.t.sent(&format!("show bgp neighbors {peer} {d}")),
                "{peer} {d}"
            );
        }
    }
    let routes = bytes(&e, bgp::ROUTES);
    assert!(routes.contains(&format!(
        "NEIGHBOR: default 192.0.2.2 received-routes\n{table}"
    )));
    assert!(routes.contains(&format!(
        "NEIGHBOR: RED 203.0.113.2 advertised-routes\n{table}"
    )));
    assert!(routes.contains("NEIGHBOR: default 198.51.100.6 routes failed\n"));
}

#[test]
fn a_state_change_alters_the_hash_of_the_neighbour_detail_and_a_counter_change_does_not() {
    check_hash(
        Vendor::Vyos,
        bgp::NEIGHBORS,
        &fixture("vyos/bgp_neighbors.json"),
        &[
            (
                "\"bgpTimerUpMsec\": 72062000",
                "\"bgpTimerUpMsec\": 75662000",
            ),
            (
                "\"bgpTimerUpString\": \"20:01:02\"",
                "\"bgpTimerUpString\": \"21:01:02\"",
            ),
            ("\"bgpTimerLastRead\": 12000", "\"bgpTimerLastRead\": 3000"),
            ("\"keepalivesSent\": 1500", "\"keepalivesSent\": 1560"),
            (
                "\"acceptedPrefixCounter\": 3",
                "\"acceptedPrefixCounter\": 4",
            ),
            (
                "\"lastResetTimerMsecs\": 72070000",
                "\"lastResetTimerMsecs\": 75670000",
            ),
            ("\"estimatedRttInMsecs\": 1", "\"estimatedRttInMsecs\": 2"),
            ("\"portLocal\": 179", "\"portLocal\": 40123"),
            ("\"portForeign\": 51234", "\"portForeign\": 51299"),
        ],
        &[
            ("\"bgpState\": \"Established\"", "\"bgpState\": \"Idle\""),
            (
                "\"remoteRouterId\": \"192.0.2.2\"",
                "\"remoteRouterId\": \"192.0.2.3\"",
            ),
        ],
    );
    check_hash(
        Vendor::Nxos,
        bgp::NEIGHBORS,
        &fixture("nxos/bgp_neighbors.json"),
        &[
            ("\"elapsedtime\": \"P1DT2H\"", "\"elapsedtime\": \"P1DT3H\""),
            ("\"lastread\": \"PT10S\"", "\"lastread\": \"PT11S\""),
            ("\"keepalive\": \"PT40S\"", "\"keepalive\": \"PT41S\""),
            ("\"msgrecvd\": \"1499\"", "\"msgrecvd\": \"1559\""),
            ("\"msgsent\": \"1500\"", "\"msgsent\": \"1560\""),
            ("\"tableversion\": \"12\"", "\"tableversion\": \"13\""),
            ("\"pfxrecvd\": \"3\"", "\"pfxrecvd\": \"4\""),
        ],
        &[
            ("\"state\": \"Established\"", "\"state\": \"Idle\""),
            (
                "\"remote-id\": \"192.0.2.2\"",
                "\"remote-id\": \"192.0.2.3\"",
            ),
            (
                "\"connectedif\": \"Ethernet1/1\"",
                "\"connectedif\": \"Ethernet1/2\"",
            ),
        ],
    );
    check_hash(
        Vendor::Iosxr,
        bgp::NEIGHBORS,
        &fixture("iosxr/bgp_neighbors.txt"),
        &[
            ("10:00:02.000", "10:01:02.000"),
            ("up for 1d02h", "up for 1d03h"),
            ("Last read 00:00:12", "Last read 00:00:13"),
            (
                "Last write 00:00:30, attempted 19, written 19",
                "Last write 00:00:31, attempted 21, written 21",
            ),
            (
                "Nov 17 10:00:00.123 last full not set pulse count 3005",
                "Nov 17 10:01:00.456 last full not set pulse count 3065",
            ),
            ("Received 1500 messages", "Received 1560 messages"),
            (
                "3 accepted prefixes, 3 are bestpaths",
                "4 accepted prefixes, 4 are bestpaths",
            ),
            ("Last ack version 12", "Last ack version 13"),
        ],
        &[
            ("BGP state = Established", "BGP state = Idle"),
            ("Remote router ID 192.0.2.2", "Remote router ID 192.0.2.3"),
        ],
    );
    check_hash(
        Vendor::Iosxe,
        bgp::NEIGHBORS,
        &fixture("iosxe/bgp_neighbors.txt"),
        &[
            ("up for 1d02h", "up for 1d03h"),
            (
                "Last read 00:00:12, last write 00:00:45",
                "Last read 00:00:02, last write 00:00:15",
            ),
            (
                "Keepalives:          1500       1499",
                "Keepalives:          1560       1559",
            ),
            (
                "Total:               1506       1507",
                "Total:               1566       1567",
            ),
            (
                "2          3 (Consumes 408 bytes)",
                "2          4 (Consumes 544 bytes)",
            ),
            ("Up: 1; Down: 0", "Up: 2; Down: 1"),
            ("mis-ordered: 0 (0 bytes)", "mis-ordered: 1 (512 bytes)"),
            ("current time is 0x5A3C1F0", "current time is 0x5A4D2E1"),
            ("Retrans          1503", "Retrans          1563"),
            (
                "iss: 2394029120  snduna: 2394057772",
                "iss: 2394029120  snduna: 2394058772",
            ),
            ("uptime: 93723045 ms", "uptime: 93783045 ms"),
            (
                "Rcvd: 3000 (out of order: 0)",
                "Rcvd: 3120 (out of order: 2)",
            ),
        ],
        &[
            ("BGP state = Established", "BGP state = Idle"),
            ("remote router ID 192.0.2.2", "remote router ID 192.0.2.3"),
            ("Connection state is ESTAB", "Connection state is CLOSED"),
        ],
    );
}

#[tokio::test(start_paused = true)]
async fn after_two_route_timeouts_in_a_row_the_other_route_commands_are_not_sent() {
    let mut e = env(Vendor::Iosxe, CaptureBgp::All);
    e.t.reply("show running-config", "hostname r1\n!\nend\n");
    e.t.reply("show ip bgp summary", &fixture("iosxe/bgp_sessions.txt"));
    e.t.reply("show bgp all neighbors", "\n");
    e.t.reply("show ip bgp neighbors 192.0.2.2 received-routes", "\n");
    e.t.fail(
        "show ip bgp neighbors 192.0.2.2 routes",
        TransportError::Timeout,
    );
    e.t.fail(
        "show ip bgp neighbors 192.0.2.2 advertised-routes",
        TransportError::Timeout,
    );
    e.c.run_cycle().await.unwrap();
    assert!(!e.t.sent("show ip bgp neighbors 198.51.100.2 received-routes"));
    let routes = bytes(&e, bgp::ROUTES);
    assert!(
        routes.starts_with("NEIGHBOR: default 192.0.2.2 received-routes\n\n"),
        "{routes}"
    );
    assert!(routes.contains("NEIGHBOR: default 192.0.2.2 routes failed\n"));
    assert!(routes.contains("NEIGHBOR: default 203.0.113.7 advertised-routes failed\n"));
    assert_eq!(
        routes.lines().filter(|l| l.ends_with(" failed")).count(),
        3 * 4 - 1
    );
}

#[tokio::test(start_paused = true)]
async fn vyos_with_all_reads_the_ipv4_unicast_neighbours_and_off_reads_no_bgp() {
    let mut e = env(Vendor::Vyos, CaptureBgp::All);
    e.t.reply(
        rsim_collect::vyos::BGP_SESSIONS_COMMAND,
        &fixture("vyos/bgp_sessions.json"),
    );
    let path = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";
    e.t.reply(
        &format!(r#"{path} vtysh -c "show ip bgp vrf all neighbors json""#),
        &fixture("vyos/bgp_neighbors.json"),
    );
    e.t.reply(
        &rsim_collect::vyos::bgp_route_command("RED", "203.0.113.2".parse().unwrap(), 1),
        r#"{"vrfId":5,"tableVersion":3,"routes":{"198.51.100.0/24":[{"valid":true}]}}"#,
    );
    e.t.reply(
        &rsim_collect::vyos::bgp_route_command("default", "192.0.2.2".parse().unwrap(), 0),
        r#"{"warning":"Inbound soft reconfiguration not enabled"}"#,
    );
    e.c.run_cycle().await.unwrap();
    let log = e.t.log.lock().unwrap().clone();
    let routes: Vec<&String> = log
        .iter()
        .filter(|c| c.contains("unicast neighbors"))
        .collect();
    assert_eq!(routes.len(), 3 * 3, "{routes:?}");
    assert!(
        !log.iter()
            .any(|c| c.contains("192.0.2.9") || c.contains("2001:db8::2"))
    );
    let v: serde_json::Value = serde_json::from_str(&bytes(&e, bgp::ROUTES)).unwrap();
    assert_eq!(
        v["RED"]["203.0.113.2"]["routes"]["answer"]["routes"]["198.51.100.0/24"][0]["valid"],
        true
    );
    assert_eq!(
        v["default"]["192.0.2.2"]["received-routes"]["answer"]["warning"],
        "Inbound soft reconfiguration not enabled"
    );
    assert!(v["default"]["198.51.100.2"]["routes"]["failed"].is_string());
    assert_eq!(
        entry(&e, bgp::NEIGHBORS).unwrap().status,
        SectionStatus::Fresh
    );

    // The same store with the setting `sessions`, then `off`.
    let dir = e.dir;
    drop(e.c);
    for (capture, sections) in [
        (CaptureBgp::Sessions, vec![bgp::SESSIONS]),
        (CaptureBgp::Off, vec![]),
    ] {
        let t = transport(&base(Vendor::Vyos));
        t.reply(
            rsim_collect::vyos::BGP_SESSIONS_COMMAND,
            &fixture("vyos/bgp_sessions.json"),
        );
        let mut c = collector(dir.path(), Vendor::Vyos, capture, source(Vendor::Vyos, &t));
        tokio::time::advance(Duration::from_secs(3600)).await;
        c.run_cycle().await.unwrap();
        let s = c.store().latest().unwrap().unwrap();
        let names: Vec<&str> = s.devices["r1"]
            .sections
            .iter()
            .map(|x| x.name.as_str())
            .filter(|n| n.starts_with("bgp_"))
            .collect();
        assert_eq!(names, sections, "{capture:?}");
    }
}

/// Runs a cycle with the sessions answer `sessions`, then a cycle with an
/// answer that is not JSON, and checks that the second cycle sends no table
/// command and stores no new blob of the tables.
async fn sessions_not_json(vendor: Vendor, command: &str, sessions: &str, garbage: &str) {
    let mut e = env(vendor, CaptureBgp::All);
    e.t.reply(command, sessions);
    e.c.run_cycle().await.unwrap();
    let first = entry(&e, bgp::ROUTES).unwrap().blob.unwrap();
    assert_ne!(bytes(&e, bgp::ROUTES), "{}");

    e.t.reply(command, garbage);
    let sent = e.t.log.lock().unwrap().len();
    tokio::time::advance(Duration::from_secs(60)).await;
    e.c.run_cycle().await.unwrap();
    let routes = entry(&e, bgp::ROUTES).unwrap();
    assert!(absent(&e, bgp::ROUTES), "{vendor}: {routes:?}");
    assert!(
        routes.blob.is_none_or(|b| b == first),
        "{vendor}: {routes:?}"
    );
    let log = e.t.log.lock().unwrap().clone();
    assert!(
        !log[sent..].iter().any(|c| c.contains("unicast neighbors")),
        "{vendor}: {log:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn sessions_that_are_not_json_give_no_new_blob_of_the_tables() {
    sessions_not_json(
        Vendor::Vyos,
        rsim_collect::vyos::BGP_SESSIONS_COMMAND,
        &fixture("vyos/bgp_sessions.json"),
        "vtysh: the daemon is not ready\n",
    )
    .await;
    sessions_not_json(
        Vendor::Nxos,
        rsim_collect::nxos::BGP_SESSIONS_COMMAND,
        &fixture("nxos/bgp_sessions.json"),
        "the BGP process is restarting\n",
    )
    .await;
}
