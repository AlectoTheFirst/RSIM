//! The ingestion of an Equinix Fabric account on synthetic sections: the
//! lowered and the unknown Fabric ports, the legs of the circuits with the
//! tags of each end, the far ends that the twin does not follow, the
//! duplicate items, the tag conflicts, the coverage and the mask.

use std::collections::BTreeMap;

use rsim_core::FunctionId;
use rsim_functions::{CircuitLeg, FarEnd, Tags, VlanTag};
use rsim_ingest::equinix::{self, Lowered, Verdict};
use rsim_ingest::estate::{Input, assemble};
use rsim_ingest::velocloud::Parsed;
use serde_json::{Value, json};

const ACCT: &str = "equinix-lab";

fn port(uuid: &str, state: &str, encapsulation: &str, tpid: Option<&str>) -> Value {
    let mut enc = json!({"type": encapsulation});
    if let Some(t) = tpid {
        enc["tagProtocolId"] = json!(t);
    }
    json!({
        "uuid": uuid,
        "name": format!("lab-{uuid}"),
        "state": state,
        "encapsulation": enc,
        "location": {"ibx": "DC1", "metroCode": "DC"},
        "physicalPorts": [{"tether": {"crossConnectId": "12345-A"}}],
        "changeLog": {"createdDateTime": "2026-01-01T00:00:00Z"},
        "operation": {"operationalStatus": "UP"},
    })
}

fn colo(port: &str, protocol: Value) -> Value {
    json!({"accessPoint": {"type": "COLO", "port": {"uuid": port}, "linkProtocol": protocol}})
}

fn dot1q(tag: i64) -> Value {
    json!({"type": "DOT1Q", "vlanTag": tag})
}

fn circuit(uuid: &str, state: Option<&str>, a: Value, z: Value) -> Value {
    let mut c = json!({"uuid": uuid, "type": "EVPL_VC", "aSide": a, "zSide": z});
    if let Some(s) = state {
        c["state"] = json!(s);
    }
    c
}

fn active(uuid: &str, a: Value, z: Value) -> Value {
    circuit(uuid, Some("ACTIVE"), a, z)
}

fn ports() -> Value {
    json!([
        port("p1", "ACTIVE", "DOT1Q", None),
        port("p2", "ACTIVE", "DOT1Q", Some("0x8100")),
        port("p3", "ACTIVE", "QINQ", Some("0x88A8")),
        port("p4", "INACTIVE", "DOT1Q", None),
        port("p5", "ACTIVE", "DOT1Q", Some("0x9100")),
        port("p6", "ACTIVE", "UNTAGGED", None),
        port("p7", "ACTIVE", "UNTAGGED", None),
        {"name": "no-uuid", "state": "ACTIVE"},
    ])
}

fn connections() -> Value {
    let sp = json!({"accessPoint": {
        "type": "SP",
        "profile": {"uuid": "sp-1", "name": "cloud-onramp-1"},
        "authenticationKey": "fake-service-key",
    }});
    let mut ip = active("c-type", colo("p1", dot1q(1300)), colo("p2", dot1q(1300)));
    ip["type"] = json!("IP_VC");
    let mut token = active("c-token", colo("p1", dot1q(1400)), json!({}));
    token["zSide"] = json!({"serviceToken": {"uuid": "tok-1"}});
    json!([
        active("c-same", colo("p1", dot1q(100)), colo("p2", dot1q(100))),
        active("c-xlate", colo("p1", dot1q(200)), colo("p2", dot1q(300))),
        active("c-sp", colo("p1", dot1q(400)), sp),
        active(
            "c-qinq",
            colo("p1", dot1q(500)),
            colo("p3", json!({"type": "QINQ", "vlanSTag": 600, "vlanCTag": 500}))
        ),
        active("c-far", colo("p2", dot1q(700)), colo("p-elsewhere", dot1q(700))),
        active("c-dup", colo("p1", dot1q(800)), colo("p2", dot1q(800))),
        active("c-dup", colo("p2", dot1q(800)), colo("p1", dot1q(800))),
        active("c-dis", colo("p1", dot1q(810)), colo("p2", dot1q(810))),
        active("c-dis", colo("p1", dot1q(810)), colo("p2", dot1q(811))),
        active("c-two-a", colo("p2", dot1q(900)), colo("p1", dot1q(901))),
        active("c-two-b", colo("p2", dot1q(900)), colo("p1", dot1q(902))),
        active("c-hair", colo("p1", dot1q(1000)), colo("p1", dot1q(1001))),
        circuit("c-ended", Some("DEPROVISIONED"), colo("p1", dot1q(1100)), colo("p2", dot1q(1100))),
        circuit("c-prov", Some("PROVISIONED"), colo("p1", dot1q(1110)), colo("p2", dot1q(1110))),
        circuit("c-nostate", None, colo("p1", dot1q(1120)), colo("p2", dot1q(1120))),
        active("c-p4", colo("p4", dot1q(100)), colo("p2", dot1q(1150))),
        active("c-tpid", colo("p5", dot1q(1200)), colo("p2", dot1q(1200))),
        ip,
        token,
        active("c-pb", colo("p6", json!({"type": "UNTAGGED"})), colo("p7", json!({"type": "NULL"}))),
        active("c-notag", colo("p1", json!({"type": "DOT1Q"})), colo("p2", dot1q(1500))),
        {"type": "EVPL_VC", "state": "ACTIVE"},
    ])
}

fn sections(m: &[(&str, Value)]) -> BTreeMap<String, (Vec<u8>, String)> {
    m.iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                (
                    serde_json::to_vec_pretty(v).unwrap(),
                    format!("{ACCT}/{k}@b1"),
                ),
            )
        })
        .collect()
}

fn parsed() -> Parsed {
    Parsed::new(&sections(&[
        ("ports", ports()),
        ("connections", connections()),
    ]))
}

fn lowered(peers: &BTreeMap<String, FunctionId>) -> Lowered {
    let account = equinix::read(ACCT, &parsed());
    equinix::lower(&account, &equinix::profile(), peers)
}

fn verdict(l: &Lowered, uuid: &str) -> Verdict {
    l.circuits
        .iter()
        .find(|c| c.uuid == uuid)
        .expect("the circuit is in the rows")
        .verdict
        .clone()
}

fn unknown(l: &Lowered, uuid: &str) -> String {
    match verdict(l, uuid) {
        Verdict::Unknown(r) => r,
        _ => panic!("the circuit is not unknown"),
    }
}

fn leg<'a>(l: &'a Lowered, port: &str, circuit: &str) -> &'a CircuitLeg {
    l.ports[port]
        .legs
        .iter()
        .find(|x| x.circuit == circuit)
        .unwrap_or_else(|| panic!("no leg of {circuit} on {port}"))
}

fn one(v: u16) -> Tags {
    Tags::one(VlanTag::dot1q(v))
}

fn far_port(l: &CircuitLeg) -> (String, Tags, String) {
    match &l.far {
        FarEnd::Port { port, tags, peer } => (port.to_string(), *tags, peer.to_string()),
        f => panic!("{f:?}"),
    }
}

fn far_sink(l: &CircuitLeg) -> String {
    match &l.far {
        FarEnd::Sink(s) => s.to_string(),
        f => panic!("{f:?}"),
    }
}

#[test]
fn a_circuit_with_one_tag_at_each_end_goes_to_the_link_peer_of_the_far_port() {
    let peers = BTreeMap::from([("p2".to_string(), FunctionId::new("sw-b/port/1/in"))]);
    let l = lowered(&peers);
    assert_eq!(verdict(&l, "c-same"), Verdict::Lowered);
    let a = leg(&l, "p1", "c-same");
    assert_eq!(a.near, one(100));
    assert_eq!(
        far_port(a),
        ("port/p2".into(), one(100), "sw-b/port/1/in".into())
    );
    let x = leg(&l, "p1", "c-xlate");
    assert_eq!(far_port(x).1, one(300));
    let back = leg(&l, "p2", "c-xlate");
    assert_eq!(back.near, one(300));
    assert_eq!(
        far_port(back),
        (
            "port/p1".into(),
            one(200),
            format!("{ACCT}/port/p1/unbound")
        )
    );
}

#[test]
fn a_qinq_end_has_the_service_tag_with_the_tpid_of_its_port() {
    let l = lowered(&BTreeMap::new());
    assert_eq!(verdict(&l, "c-qinq"), Verdict::Lowered);
    let qinq = Tags::two(
        VlanTag {
            vlan: 600,
            tpid: 0x88a8,
        },
        VlanTag::dot1q(500),
    );
    assert_eq!(leg(&l, "p3", "c-qinq").near, qinq);
    assert_eq!(far_port(leg(&l, "p1", "c-qinq")).1, qinq);
    let tpid = leg(&l, "p5", "c-tpid");
    assert_eq!(
        tpid.near,
        Tags::one(VlanTag {
            vlan: 1200,
            tpid: 0x9100
        })
    );
    assert_eq!(far_port(leg(&l, "p2", "c-tpid")).1, tpid.near);
}

#[test]
fn a_port_based_circuit_carries_each_frame_with_its_tags() {
    let l = lowered(&BTreeMap::new());
    assert_eq!(verdict(&l, "c-pb"), Verdict::Lowered);
    assert!(leg(&l, "p6", "c-pb").port_based);
    assert!(leg(&l, "p7", "c-pb").port_based);
    assert_eq!(far_port(leg(&l, "p6", "c-pb")).0, "port/p7");
}

#[test]
fn an_end_that_the_twin_does_not_follow_sends_its_frames_to_a_sink() {
    let l = lowered(&BTreeMap::new());
    let sink = |c: &str| format!("{ACCT}/circuit/{c}/sink");
    for (c, port, reason) in [
        (
            "c-sp",
            "p1",
            "the far end is the service profile cloud-onramp-1",
        ),
        ("c-far", "p2", "the far end is outside the account"),
        (
            "c-prov",
            "p1",
            "the circuit state PROVISIONED is not handled",
        ),
        ("c-nostate", "p1", "the circuit has no state"),
        ("c-type", "p1", "the circuit type IP_VC is not handled"),
        ("c-token", "p1", "an end has no type or no port"),
        (
            "c-p4",
            "p2",
            "the state INACTIVE of the Fabric port lab-p4 is not handled",
        ),
        (
            "c-notag",
            "p2",
            "the DOT1Q end on the Fabric port lab-p1 has no tag",
        ),
    ] {
        assert_eq!(unknown(&l, c), reason, "{c}");
        assert_eq!(far_sink(leg(&l, port, c)), sink(c), "{c}");
    }
    assert!(
        l.notes
            .iter()
            .any(|n| n == "c-far: the far end is outside the account")
    );
}

#[test]
fn duplicate_items_merge_when_they_agree_in_either_order() {
    let l = lowered(&BTreeMap::new());
    assert_eq!(verdict(&l, "c-dup"), Verdict::Lowered);
    let dup = l.circuits.iter().find(|c| c.uuid == "c-dup").unwrap();
    assert_eq!(dup.spans.len(), 2);
    assert_eq!(leg(&l, "p1", "c-dup").spans.len(), 2);
    assert_eq!(
        unknown(&l, "c-dis"),
        "the 2 items of the circuit c-dis differ"
    );
}

#[test]
fn two_circuits_on_one_tag_and_a_hairpin_circuit_are_unknown() {
    let l = lowered(&BTreeMap::new());
    let r = "2 circuits use VLAN 900 on the Fabric port lab-p2";
    assert_eq!(unknown(&l, "c-two-a"), r);
    assert_eq!(unknown(&l, "c-two-b"), r);
    assert_eq!(
        unknown(&l, "c-hair"),
        "the circuit has both ends on the Fabric port lab-p1"
    );
    assert!(l.notes.iter().any(|n| n == &format!("c-two-a: {r}")));
}

#[test]
fn an_ended_circuit_has_no_leg_and_a_port_that_is_not_lowered_has_no_circuit() {
    let l = lowered(&BTreeMap::new());
    assert_eq!(verdict(&l, "c-ended"), Verdict::Ended);
    assert!(l.ports["p1"].legs.iter().all(|x| x.circuit != "c-ended"));
    assert_eq!(
        l.ports["p4"].reason.as_deref(),
        Some("the state INACTIVE of the Fabric port lab-p4 is not handled")
    );
    assert!(l.ports["p4"].legs.is_empty());
    let ids: Vec<String> = l.functions.iter().map(|f| f.id().to_string()).collect();
    assert!(ids.contains(&format!("{ACCT}/port/p4/in")));
    assert!(!ids.contains(&format!("{ACCT}/port/p4/circuit")));
    assert!(ids.contains(&format!("{ACCT}/port/p1/circuit")));
    assert!(l.notes.iter().any(|n| n == "ports: item 8 has no uuid"));
    assert!(
        l.notes
            .iter()
            .any(|n| n == "connections: item 22 has no uuid")
    );
}

#[test]
fn a_repeated_fabric_port_has_one_gate_and_is_not_lowered_when_its_items_differ() {
    let mut list = ports();
    let items = list.as_array_mut().unwrap();
    items.push(port("p1", "ACTIVE", "DOT1Q", None));
    items.push(port("p2", "ACTIVE", "QINQ", None));
    let s = sections(&[("ports", list), ("connections", connections())]);
    let account = equinix::read(ACCT, &Parsed::new(&s));
    assert_eq!(account.ports.iter().filter(|p| p.uuid == "p1").count(), 1);
    let l = equinix::lower(&account, &equinix::profile(), &BTreeMap::new());
    assert_eq!(l.ports["p1"].reason, None);
    let r = "the 2 items of the Fabric port p2 differ";
    assert_eq!(l.ports["p2"].reason.as_deref(), Some(r));
    assert!(l.notes.iter().any(|n| n == r));
    let ids: Vec<String> = l.functions.iter().map(|f| f.id().to_string()).collect();
    let mut once = ids.clone();
    once.sort();
    once.dedup();
    assert_eq!(ids.len(), once.len());
    let e = assemble(vec![Input::Equinix {
        name: ACCT.into(),
        sections: s,
    }]);
    e.builder.build().expect("the twin builds");
}

#[test]
fn the_twin_of_an_account_builds_the_same_way_twice() {
    let input = || Input::Equinix {
        name: ACCT.into(),
        sections: sections(&[("ports", ports()), ("connections", connections())]),
    };
    let one = assemble(vec![input()]);
    let two = assemble(vec![input()]);
    assert_eq!(one.notes[ACCT], two.notes[ACCT]);
    let ids = |e: rsim_ingest::estate::Estate| -> Vec<String> {
        let t = e.builder.build().expect("the twin builds");
        let mut v: Vec<String> = t.functions().map(|f| f.id().to_string()).collect();
        v.sort();
        v
    };
    assert_eq!(ids(one), ids(two));
}

#[test]
fn the_coverage_lists_the_paths_that_no_reader_reads() {
    let cov = equinix::coverage::classify(&parsed());
    let paths: Vec<&str> = cov.unhandled.keys().map(String::as_str).collect();
    assert!(paths.contains(&"ports/*/operation"), "{paths:?}");
    assert!(
        paths.contains(&"connections/*/zSide/serviceToken"),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"connections/*/zSide/accessPoint/authenticationKey"),
        "{paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("linkProtocol")),
        "{paths:?}"
    );
}

#[test]
fn a_masked_connection_shows_no_service_key() {
    let bytes = serde_json::to_vec_pretty(&connections()).unwrap();
    let lines = rsim_ingest::mask::section_lines(
        "equinix",
        "connections",
        rsim_store::Format::Json,
        &bytes,
    )
    .unwrap();
    let text = lines.join("\n");
    assert!(!text.contains("fake-service-key"), "{text}");
    assert!(text.contains("authenticationKey"));
}
