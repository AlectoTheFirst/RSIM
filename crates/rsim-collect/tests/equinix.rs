//! The Equinix source on a fake API: the order and the bodies of the reads,
//! the paging, the dependent reads, the Network Edge sections, the failed
//! reads, the secrets and the change hashes of 2 cycles.

#![cfg(feature = "equinix")]

use std::sync::Arc;
use std::time::Duration;

use rsim_collect::equinix::{
    Account, DEVICE_PROPERTIES, EDGE_DEVICES, EDGE_LINKS, EquinixSource, PORT_PROPERTIES, PORTS,
    SEARCH, search_body,
};
use rsim_collect::fake::FakeTransport;
use rsim_collect::redact::REDACTED;
use rsim_collect::*;
use rsim_store::Store;
use serde_json::{Value, json};

#[path = "support/keys.rs"]
mod keys;

/// 2026-11-23 08:00:00 UTC.
const T0: u64 = 1_795_420_800_000;
const ID: &str = "equinix-lab";
const INTERVAL: Duration = Duration::from_secs(900);

fn device() -> Device {
    Device {
        id: ID.into(),
        vendor: Vendor::Equinix,
        address: "https://api.equinix.com".into(),
        credential: ID.into(),
        site: None,
        capture_bgp: Default::default(),
        route: Default::default(),
        interval: INTERVAL,
    }
}

fn get(path: &str, offset: usize, limit: u32) -> String {
    format!("{path}?offset={offset}&limit={limit}")
}

fn search(properties: [&str; 2], values: &[&str], offset: usize, limit: u32) -> String {
    let values: Vec<String> = values.iter().map(|v| v.to_string()).collect();
    format!(
        "POST {SEARCH} {}",
        search_body(properties, &values, offset, limit)
    )
}

fn port(uuid: &str) -> Value {
    json!({
        "uuid": uuid,
        "name": format!("lab-{uuid}"),
        "state": "ACTIVE",
        "encapsulation": {"type": "DOT1Q", "tagProtocolId": "0x8100"},
        "changeLog": {"createdDateTime": "2026-01-01T00:00:00Z"},
    })
}

fn connection(uuid: &str, a: &str, z: &str, changed: &str) -> Value {
    let end = |p: &str| {
        json!({"accessPoint": {
            "type": "COLO",
            "port": {"uuid": p},
            "linkProtocol": {"type": "DOT1Q", "vlanTag": 100},
            "authenticationKey": "fake-service-key",
        }})
    };
    json!({
        "uuid": uuid,
        "type": "EVPL_VC",
        "state": "ACTIVE",
        "aSide": end(a),
        "zSide": end(z),
        "changeLog": {"updatedDateTime": changed},
    })
}

fn page(items: Value, total: usize) -> Vec<u8> {
    json!({"data": items, "pagination": {"total": total, "offset": 0}})
        .to_string()
        .into_bytes()
}

fn ok(t: &FakeTransport, command: &str, body: Vec<u8>) {
    t.reply(ID, command, Ok(body));
}

fn source(t: &Arc<FakeTransport>, account: Account) -> EquinixSource {
    EquinixSource::new(t.clone()).with_account(ID, account)
}

async fn fetch(src: &EquinixSource) -> Vec<RawSection> {
    src.fetch(&device(), Timeouts::from(Duration::from_secs(300)))
        .await
}

fn by_name<'a>(sections: &'a [RawSection], name: &str) -> &'a Result<Vec<u8>, TransportError> {
    &sections
        .iter()
        .find(|s| s.spec.name == name)
        .unwrap()
        .result
}

fn json_of(r: &Result<Vec<u8>, TransportError>) -> Value {
    serde_json::from_slice(r.as_ref().unwrap()).unwrap()
}

fn commands(t: &FakeTransport) -> Vec<String> {
    t.log().into_iter().map(|(_, c)| c).collect()
}

/// The ports p1, p2 and p3 on 2 pages of 2 with a total, and one connection
/// page as a list.
fn account_api(t: &FakeTransport, changed: &str) {
    ok(
        t,
        &get(PORTS, 0, 2),
        page(json!([port("p3"), port("p1")]), 3),
    );
    ok(t, &get(PORTS, 2, 2), page(json!([port("p2")]), 3));
    ok(
        t,
        &search(PORT_PROPERTIES, &["p1", "p2", "p3"], 0, 2),
        json!([connection("c2", "p1", "p2", changed)])
            .to_string()
            .into_bytes(),
    );
}

fn small_pages() -> Account {
    Account {
        network_edge: false,
        page_size: 2,
    }
}

#[tokio::test]
async fn the_ports_and_their_connections_read_in_order_with_all_pages() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    account_api(&t, "2026-01-01T00:00:00Z");
    let out = fetch(&source(&t, small_pages())).await;
    let names: Vec<&str> = out.iter().map(|s| s.spec.name).collect();
    assert_eq!(names, ["ports", "connections"]);
    assert_eq!(
        commands(&t),
        [
            get(PORTS, 0, 2),
            get(PORTS, 2, 2),
            search(PORT_PROPERTIES, &["p1", "p2", "p3"], 0, 2)
        ]
    );
    let ports = json_of(by_name(&out, "ports"));
    let uuids: Vec<&str> = ports
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["uuid"].as_str().unwrap())
        .collect();
    assert_eq!(uuids, ["p1", "p2", "p3"]);
    let c = json_of(by_name(&out, "connections"));
    assert_eq!(c[0]["aSide"]["accessPoint"]["authenticationKey"], REDACTED);
    assert_eq!(c[0]["aSide"]["accessPoint"]["linkProtocol"]["vlanTag"], 100);
}

#[tokio::test]
async fn a_page_with_no_total_ends_the_read_when_it_is_short_or_empty() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(
        &t,
        &get(PORTS, 0, 2),
        json!([port("p1"), port("p2")]).to_string().into_bytes(),
    );
    ok(&t, &get(PORTS, 2, 2), b"[]".to_vec());
    ok(
        &t,
        &search(PORT_PROPERTIES, &["p1", "p2"], 0, 2),
        page(json!([]), 0),
    );
    let out = fetch(&source(&t, small_pages())).await;
    assert_eq!(json_of(by_name(&out, "ports")).as_array().unwrap().len(), 2);
    assert_eq!(json_of(by_name(&out, "connections")), json!([]));
    assert_eq!(t.calls(), 3);
}

#[tokio::test]
async fn an_empty_page_before_the_total_fails_the_section() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(
        &t,
        &get(PORTS, 0, 2),
        page(json!([port("p1"), port("p2")]), 5),
    );
    ok(&t, &get(PORTS, 2, 2), page(json!([]), 5));
    let out = fetch(&source(&t, small_pages())).await;
    assert_eq!(
        by_name(&out, "ports"),
        &Err(TransportError::Command(format!(
            "{PORTS}: paging stopped at 2 of 5 items"
        )))
    );
    assert_eq!(
        by_name(&out, "connections"),
        &Err(TransportError::Command(
            "not sent: the read of ports failed".into()
        ))
    );
    assert_eq!(t.calls(), 2);
}

#[tokio::test]
async fn an_account_with_no_port_sends_no_search() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(&t, &get(PORTS, 0, 100), page(json!([]), 0));
    let out = fetch(&source(&t, Account::default())).await;
    assert_eq!(json_of(by_name(&out, "ports")), json!([]));
    assert_eq!(json_of(by_name(&out, "connections")), json!([]));
    assert_eq!(commands(&t), [get(PORTS, 0, 100)]);
}

#[tokio::test]
async fn a_status_fails_its_section_with_its_reason() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(&t, &get(PORTS, 0, 100), page(json!([port("p1")]), 1));
    t.reply_status(
        ID,
        &search(PORT_PROPERTIES, &["p1"], 0, 100),
        400,
        "{\"errorCode\":\"EQ-3040016\"}",
    );
    let out = fetch(&source(&t, Account::default())).await;
    let Err(TransportError::Command(e)) = by_name(&out, "connections") else {
        panic!("a 400 of the search fails the section");
    };
    assert!(
        e.starts_with(&format!("HTTP 400 for {SEARCH}")) && e.contains("EQ-3040016"),
        "{e}"
    );

    for (status, want) in [(403, "not authorized"), (429, "rate")] {
        let t = Arc::new(FakeTransport::new(Duration::ZERO));
        t.reply_status(ID, &get(PORTS, 0, 100), status, "{\"error\":\"rate\"}");
        let out = fetch(&source(&t, Account::default())).await;
        let Err(TransportError::Command(e)) = by_name(&out, "ports") else {
            panic!("HTTP {status} fails the section");
        };
        assert!(e.contains(want), "{e}");
    }
}

#[tokio::test]
async fn a_login_that_fails_fails_each_section_and_sends_nothing_more() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    let login =
        TransportError::Connect("the token request of the client lab-id gave HTTP 401".into());
    t.reply(ID, &get(PORTS, 0, 100), Err(login.clone()));
    let account = Account {
        network_edge: true,
        page_size: 100,
    };
    let out = fetch(&source(&t, account)).await;
    assert_eq!(out.len(), 5);
    assert!(out.iter().all(|s| s.result == Err(login.clone())));
    assert_eq!(t.calls(), 1);
}

fn edge_device(uuid: &str) -> Value {
    json!({
        "uuid": uuid,
        "name": "ne-1",
        "deviceTypeCode": "C8000V",
        "vendorConfig": {"adminPassword": "fake-admin"},
        "interfaces": [{"id": 3, "name": "GigabitEthernet3", "macAddress": "00:00:5e:00:53:01"}],
    })
}

#[tokio::test]
async fn network_edge_reads_the_devices_the_links_and_their_connections() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(&t, &get(PORTS, 0, 100), page(json!([]), 0));
    ok(
        &t,
        &get(EDGE_DEVICES, 0, 100),
        page(json!([edge_device("d1")]), 1),
    );
    ok(
        &t,
        &get(EDGE_LINKS, 0, 100),
        page(
            json!([{"uuid": "l1", "groupName": "lg", "linkDevices": []}]),
            1,
        ),
    );
    ok(
        &t,
        &search(DEVICE_PROPERTIES, &["d1"], 0, 100),
        page(json!([]), 0),
    );
    let account = Account {
        network_edge: true,
        page_size: 100,
    };
    let src = source(&t, account);
    assert_eq!(src.sections(&device()).len(), 5);
    let out = fetch(&src).await;
    assert!(out.iter().all(|s| s.result.is_ok()), "{out:?}");
    let devices = json_of(by_name(&out, "edge_devices"));
    assert_eq!(devices[0]["vendorConfig"], REDACTED);
    assert_eq!(
        devices[0]["interfaces"][0]["macAddress"],
        "00:00:5e:00:53:01"
    );
    assert_eq!(
        commands(&t),
        [
            get(PORTS, 0, 100),
            get(EDGE_DEVICES, 0, 100),
            get(EDGE_LINKS, 0, 100),
            search(DEVICE_PROPERTIES, &["d1"], 0, 100),
        ]
    );
}

#[tokio::test]
async fn an_account_with_no_network_edge_has_the_edge_sections_absent() {
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    ok(&t, &get(PORTS, 0, 100), page(json!([]), 0));
    t.reply_status(ID, &get(EDGE_DEVICES, 0, 100), 404, "{}");
    t.reply_status(ID, &get(EDGE_LINKS, 0, 100), 404, "{}");
    let account = Account {
        network_edge: true,
        page_size: 100,
    };
    let out = fetch(&source(&t, account)).await;
    for name in ["edge_devices", "edge_links", "edge_connections"] {
        let s = out.iter().find(|s| s.spec.name == name).unwrap();
        assert!(s.absent(), "{name}: {:?}", s.result);
    }
    assert!(
        !out.iter()
            .any(|s| s.spec.name == "connections" && s.result.is_err())
    );
    assert_eq!(t.calls(), 3);
}

/// The scheduler forces each collection of a device whose interval is
/// 900 s or more, so the test of the keep lists uses 60 s.
#[tokio::test(start_paused = true)]
async fn a_cycle_with_only_a_changed_time_writes_no_snapshot() {
    let minute = Duration::from_secs(60);
    let dev = Device {
        interval: minute,
        ..device()
    };
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TokioClock::new(T0));
    let store = Store::open(dir.path(), keys::keys()).unwrap();
    let t = Arc::new(FakeTransport::new(Duration::ZERO));
    account_api(&t, "2026-01-01T00:00:00Z");
    let mut c = Collector::new(
        store,
        Box::new(vec![dev]),
        Schedule {
            spread: false,
            ..Schedule::default()
        },
        Limits::default(),
        clock.clone(),
    )
    .unwrap()
    .with_source(Arc::new(source(&t, small_pages())));
    let r = c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    assert!(r.snapshot.is_some());

    tokio::time::advance(minute).await;
    account_api(&t, "2026-06-01T00:00:00Z");
    let r = c.run_cycle().await.unwrap();
    assert!(r.failed.is_empty(), "{r:?}");
    assert_eq!(r.snapshot, None);

    tokio::time::advance(minute).await;
    let mut ended = connection("c2", "p1", "p2", "2026-06-01T00:00:00Z");
    ended["state"] = json!("DEPROVISIONED");
    ok(
        &t,
        &search(PORT_PROPERTIES, &["p1", "p2", "p3"], 0, 2),
        json!([ended]).to_string().into_bytes(),
    );
    let r = c.run_cycle().await.unwrap();
    assert!(r.snapshot.is_some(), "{r:?}");
}
