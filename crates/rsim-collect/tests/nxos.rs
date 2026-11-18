//! Collection cycles of an NX-OS switch on the fake transport, with the
//! synthetic answers in `tests/fixtures/nxos/`.

#![cfg(feature = "nxos")]

use std::sync::Arc;
use std::time::Duration;

use arrow_array::{Array, BooleanArray, StringArray, UInt64Array};
use rsim_collect::fake::FakeTransport;
use rsim_collect::nxos::{NxosSource, sections};
use rsim_collect::*;
use rsim_store::{
    Keys, LINK_SPEEDS, LINKS, MAC_TABLE, NEIGHBOURS, ROUTES, SectionStatus, Snapshot, Store,
    TableSchema,
};

const T0: u64 = 1_700_000_000_000;

fn fixture(name: &str) -> String {
    let p = format!("{}/tests/fixtures/nxos/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn switch() -> Device {
    Device {
        id: "n1".into(),
        vendor: Vendor::Nxos,
        address: "192.0.2.10".into(),
        credential: "lab".into(),
        site: None,
        capture_bgp: Default::default(),
        route: Default::default(),
    }
}

/// The fixture of each section that has one. The other commands are
/// refused as on a switch with no such feature.
fn file(section: &str) -> Option<&'static str> {
    Some(match section {
        "config" => "config.txt",
        "version" => "version.json",
        "interfaces" => "interface.json",
        "lldp" => "lldp.json",
        "vlans" => "vlan.json",
        "vrfs" => "vrf.json",
        "rib" => "route.json",
        "mac_table" => "mac.json",
        "arp" => "arp.json",
        "vrf_interfaces" => "vrf_interface.json",
        "stp" => "stp.json",
        "nve_peers" => "nve_peers.json",
        "nve_vnis" => "nve_vni.json",
        "evpn_macs" => "evpn_mac.json",
        "evpn_mac_ips" => "evpn_mac_ip.json",
        "mroutes" => "mroute.json",
        "pim_neighbors" => "pim.json",
        _ => return None,
    })
}

fn command(section: &str) -> String {
    sections(false)
        .into_iter()
        .find(|s| s.name == section)
        .unwrap()
        .command
}

fn set(t: &FakeTransport, section: &str, text: &str) {
    t.reply("n1", &command(section), Ok(text.as_bytes().to_vec()));
}

fn load(t: &FakeTransport) {
    for s in sections(false) {
        match (s.name, file(s.name)) {
            (_, Some(f)) => set(t, s.name, &fixture(f).replace("HOST", "n1")),
            ("cdp", None) => set(t, "cdp", "Note: CDP not enabled\n"),
            ("acl" | "trunks", None) => set(t, s.name, "\n"),
            (_, None) => t.reply(
                "n1",
                &s.command,
                Err(TransportError::Command(format!(
                    "exit status 16: Syntax error while parsing '{}'",
                    s.command
                ))),
            ),
        }
    }
}

struct Env {
    _dir: tempfile::TempDir,
    t: Arc<FakeTransport>,
    c: Collector,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let t = Arc::new(FakeTransport::new(Duration::from_millis(1)));
    load(&t);
    let store = Store::open(dir.path(), Keys::new([1; 32], [2; 32])).unwrap();
    let c = Collector::new(
        store,
        Box::new(vec![switch()]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        Arc::new(TokioClock::new(T0)),
    )
    .unwrap()
    .with_source(Arc::new(NxosSource::new(t.clone())));
    Env { _dir: dir, t, c }
}

fn latest(e: &Env) -> Snapshot {
    e.c.store().latest().unwrap().unwrap()
}

fn status(e: &Env, section: &str) -> SectionStatus {
    latest(e).devices["n1"]
        .sections
        .iter()
        .find(|s| s.name == section)
        .unwrap()
        .status
        .clone()
}

fn rows(e: &Env, t: &TableSchema) -> Vec<Vec<String>> {
    let s = latest(e);
    let all = e.c.store().read_table(&s, t).unwrap();
    let Some((_, b)) = all.into_iter().find(|(d, _)| d == "n1") else {
        return Vec::new();
    };
    (0..b.num_rows())
        .map(|i| {
            t.columns
                .iter()
                .map(|c| {
                    let a = b.column_by_name(c.name).unwrap();
                    if a.is_null(i) {
                        return "-".to_string();
                    }
                    let any = a.as_any();
                    if let Some(x) = any.downcast_ref::<StringArray>() {
                        x.value(i).to_string()
                    } else if let Some(x) = any.downcast_ref::<UInt64Array>() {
                        x.value(i).to_string()
                    } else {
                        any.downcast_ref::<BooleanArray>()
                            .unwrap()
                            .value(i)
                            .to_string()
                    }
                })
                .collect()
        })
        .collect()
}

fn blob(e: &Env, section: &str) -> String {
    let s = latest(e);
    let entry = s.devices["n1"]
        .sections
        .iter()
        .find(|x| x.name == section)
        .unwrap()
        .clone();
    String::from_utf8(e.c.store().read_blob(entry.blob.as_ref().unwrap()).unwrap()).unwrap()
}

fn v(row: &[&str]) -> Vec<String> {
    row.iter().map(|x| (*x).to_string()).collect()
}

#[tokio::test(start_paused = true)]
async fn the_first_cycle_fills_the_tables() {
    let mut e = env();
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some() && r.failed.is_empty(), "{r:?}");
    assert!(r.extract_errors.is_empty(), "{:?}", r.extract_errors);
    assert_eq!(status(&e, "config"), SectionStatus::Fresh);
    assert!(matches!(status(&e, "cdp"), SectionStatus::Absent { .. }));
    assert!(matches!(status(&e, "hsrp"), SectionStatus::Absent { .. }));
    assert_eq!(status(&e, "stp"), SectionStatus::Fresh);
    assert_eq!(status(&e, "acl"), SectionStatus::Fresh);
    assert_eq!(blob(&e, "acl").trim(), "{}");
    assert_eq!(
        rows(&e, &LINKS),
        [
            v(&[
                "Ethernet1/1",
                "00:00:5e:00:53:01",
                "9216",
                "true",
                "up",
                "-",
                "-"
            ]),
            v(&[
                "Ethernet1/2",
                "00:00:5e:00:53:02",
                "1500",
                "true",
                "up",
                "-",
                "-"
            ]),
            v(&[
                "Vlan10",
                "00:00:5e:00:53:10",
                "1500",
                "true",
                "up",
                "-",
                "10"
            ]),
        ]
    );
    assert_eq!(
        rows(&e, &rsim_store::ADDRESSES),
        [
            v(&["Ethernet1/2", "198.51.100.1/24"]),
            v(&["Vlan10", "192.0.2.1/24"])
        ]
    );
    assert_eq!(
        rows(&e, &LINK_SPEEDS),
        [
            v(&["Ethernet1/1", "10000", "full"]),
            v(&["Ethernet1/2", "1000", "-"])
        ]
    );
    assert_eq!(
        rows(&e, &ROUTES),
        [
            v(&[
                "default",
                "192.0.2.0/24",
                "direct",
                "true",
                "0",
                "0",
                "-",
                "Vlan10"
            ]),
            v(&[
                "default",
                "0.0.0.0/0",
                "static",
                "true",
                "1",
                "0",
                "198.51.100.254%RED",
                "Ethernet1/2"
            ]),
            v(&[
                "default",
                "0.0.0.0/0",
                "bgp-65001",
                "false",
                "20",
                "0",
                "203.0.113.9",
                "-"
            ]),
            v(&[
                "RED",
                "198.51.100.0/24",
                "direct",
                "true",
                "0",
                "0",
                "-",
                "Ethernet1/2"
            ]),
            v(&[
                "RED",
                "203.0.113.20/32",
                "bgp-65001",
                "true",
                "200",
                "0",
                "192.0.2.2",
                "-"
            ]),
        ]
    );
    assert_eq!(
        rows(&e, &MAC_TABLE),
        [v(&["10", "00:00:5e:00:53:20", "Ethernet1/1", "dynamic"])]
    );
    assert_eq!(
        rows(&e, &NEIGHBOURS),
        [v(&["Vlan10", "192.0.2.20", "00:00:5e:00:53:20", "-"])]
    );
    let rib = blob(&e, "rib");
    assert!(rib.contains("\"ROW_addrf\":["), "{rib}");
    assert!(!rib.contains("\"ROW_path\":{"), "{rib}");
    for s in [
        "nve_peers",
        "nve_vnis",
        "evpn_macs",
        "evpn_mac_ips",
        "mroutes",
        "pim_neighbors",
    ] {
        assert_eq!(status(&e, s), SectionStatus::Fresh, "{s}");
    }
    let one = blob(&e, "evpn_mac_ips");
    assert!(one.contains("\"ROW_l2route_evpn_mac_ip_all\":["), "{one}");
    let oif = blob(&e, "mroutes");
    assert!(oif.contains("\"ROW_oif\":["), "{oif}");
}

#[tokio::test(start_paused = true)]
async fn the_tunnel_and_multicast_state_changes_make_a_snapshot_and_their_times_do_not() {
    let mut e = env();
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let swap = |f: &str, a: &str, b: &str| fixture(f).replace("HOST", "n1").replace(a, b);
    set(&e.t, "nve_peers", &swap("nve_peers.json", "P2D", "P3D"));
    set(
        &e.t,
        "mroutes",
        &swap(
            "mroute.json",
            "\"oif-uptime\": \"P1D\"",
            "\"oif-uptime\": \"P2D\"",
        ),
    );
    set(&e.t, "pim_neighbors", &swap("pim.json", "PT1M30S", "PT1M"));
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);

    for (section, file, a, b) in [
        (
            "nve_peers",
            "nve_peers.json",
            "\"peer-state\": \"Up\", \"learn-type\": \"CP\", \"uptime\": \"P2D\"",
            "\"peer-state\": \"Down\", \"learn-type\": \"CP\", \"uptime\": \"P2D\"",
        ),
        (
            "mroutes",
            "mroute.json",
            "\"oif-name\": \"nve1\"",
            "\"oif-name\": \"Ethernet1/2\"",
        ),
        (
            "rib",
            "route.json",
            "\"segid\": \"50001\"",
            "\"segid\": \"50002\"",
        ),
    ] {
        set(&e.t, section, &swap(file, a, b));
        tokio::time::advance(Duration::from_secs(60)).await;
        let r = e.c.run_cycle().await.unwrap();
        assert!(r.snapshot.is_some(), "{section}");
    }
}

#[tokio::test(start_paused = true)]
async fn counters_and_ages_make_no_snapshot() {
    let mut e = env();
    let first = e.c.run_cycle().await.unwrap().snapshot.unwrap();
    let swap = |f: &str, a: &str, b: &str| fixture(f).replace("HOST", "n1").replace(a, b);
    set(
        &e.t,
        "interfaces",
        &swap(
            "interface.json",
            "\"eth_inpkts\": 1000",
            "\"eth_inpkts\": 9999",
        ),
    );
    set(
        &e.t,
        "version",
        &swap(
            "version.json",
            "\"kern_uptm_secs\": 3",
            "\"kern_uptm_secs\": 59",
        ),
    );
    set(&e.t, "rib", &swap("route.json", "P1D", "P1DT1M"));
    set(&e.t, "mac_table", &swap("mac.json", "\"120\"", "\"180\""));
    set(&e.t, "arp", &swap("arp.json", "00:01:02", "00:02:02"));
    set(&e.t, "lldp", &swap("lldp.json", "120", "90"));
    set(&e.t, "config", &swap("config.txt", "10:01:00", "10:02:00"));
    set(
        &e.t,
        "stp",
        &swap(
            "stp.json",
            "\"topology_change\": \"5\"",
            "\"topology_change\": \"6\"",
        ),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert_eq!(r.snapshot, None, "{r:?}");
    assert_eq!(latest(&e).manifest.cycle, first);

    set(
        &e.t,
        "interfaces",
        &swap(
            "interface.json",
            "\"state\": \"up\", \"admin_state\": \"up\", \"eth_hw_addr\": \"0000.5e00.5301\"",
            "\"state\": \"down\", \"admin_state\": \"up\", \"eth_hw_addr\": \"0000.5e00.5301\"",
        ),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some());
    assert_eq!(rows(&e, &LINKS)[0][4], "down");

    // The mode of a port is a kept field.
    set(
        &e.t,
        "interfaces",
        &swap(
            "interface.json",
            "\"eth_mode\": \"trunk\"",
            "\"eth_mode\": \"access\"",
        ),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_text_answer_to_a_json_command_fails_alone() {
    let mut e = env();
    set(&e.t, "vlans", "% Some text that is not JSON\nmore text\n");
    set(&e.t, "vrfs", "Note: unexpected\n{}");
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some());
    assert!(
        matches!(status(&e, "vlans"), SectionStatus::Missing { .. }),
        "{:?}",
        status(&e, "vlans")
    );
    assert!(matches!(status(&e, "vrfs"), SectionStatus::Missing { .. }));
    assert_eq!(status(&e, "interfaces"), SectionStatus::Fresh);
    assert_eq!(rows(&e, &LINKS).len(), 3);
}

#[tokio::test(start_paused = true)]
async fn an_answer_of_another_shape_is_an_extract_error() {
    let mut e = env();
    set(&e.t, "interfaces", r#"{"unexpected": 1}"#);
    set(&e.t, "rib", "{}");
    let r = e.c.run_cycle().await.unwrap();
    let errors: Vec<&str> = r.extract_errors.iter().map(|x| x.2.as_str()).collect();
    assert_eq!(
        errors,
        [
            "addresses: the answer has no TABLE_interface",
            "link_speeds: the answer has no TABLE_interface",
            "links: the answer has no TABLE_interface",
        ]
    );
    assert!(rows(&e, &ROUTES).is_empty(), "{{}} is an empty route table");
}

#[tokio::test(start_paused = true)]
async fn an_absent_arp_section_leaves_no_rows() {
    let mut e = env();
    e.c.run_cycle().await.unwrap();
    assert!(!rows(&e, &NEIGHBOURS).is_empty());
    e.t.reply(
        "n1",
        &command("arp"),
        Err(TransportError::NotFound("% Invalid command".into())),
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    let r = e.c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some(), "{r:?}");
    assert!(matches!(status(&e, "arp"), SectionStatus::Absent { .. }));
    assert_eq!(rows(&e, &NEIGHBOURS), Vec::<Vec<String>>::new());
    assert_eq!(latest(&e).devices["n1"].tables["neighbours"].rows, 0);
}

#[tokio::test(start_paused = true)]
async fn a_dead_switch_gets_no_more_commands() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = AtomicUsize::new(0);
    let n = sections(false).len();
    let out = fetch_sections(sections(false), Duration::from_secs(5), true, |_c| {
        calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TransportError::Connect("device 192.0.2.10: refused".into())) })
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(out.len(), n);
    assert!(matches!(&out[1].result, Err(TransportError::Connect(e)) if e.starts_with("not sent")));

    let calls = AtomicUsize::new(0);
    let out = fetch_sections(sections(false), Duration::from_secs(5), true, |_c| {
        calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(&out[2].result, Err(TransportError::Connect(e)) if e.contains("timed out")));
}
