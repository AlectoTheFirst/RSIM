//! The Network Edge part of an Equinix account on synthetic sections: the
//! circuit ends on a Network Edge interface, the device link groups, the
//! bindings of the Network Edge devices and the coverage.

use std::collections::BTreeMap;

use rsim_core::{FunctionId, Mac, NetFunction};
use rsim_functions::FarEnd;
use rsim_ingest::equinix::{self, Lowered, Verdict};
use rsim_ingest::links::Summary;
use rsim_ingest::velocloud::Parsed;
use serde_json::{Value, json};

const ACCT: &str = "equinix-lab";
const FW: &str = "bbbbbbbb-0000-4000-8000-0000000000f1";
const RTR: &str = "bbbbbbbb-0000-4000-8000-0000000000a1";
const HUB: &str = "bbbbbbbb-0000-4000-8000-0000000000b1";
const FW_ETH0: &str = "cccccccc-0000-4000-8000-0000000000f0";
const FW_MAC: &str = "00:00:5e:00:53:31";

fn interface(id: i64, name: &str, mac: Option<&str>) -> Value {
    let mut i = json!({"id": id, "name": name, "type": "DATA", "status": "ASSIGNED",
                       "uuid": format!("{name}-uuid")});
    if let Some(m) = mac {
        i["macAddress"] = json!(m);
    }
    i
}

fn edge_devices() -> Value {
    json!([
        {
            "uuid": FW, "name": "lab-fw", "hostName": "lab-fw-host",
            "deviceTypeCode": "FW-CODE", "deviceTypeVendor": "Vendor A",
            "deviceTypeCategory": "FIREWALL", "status": "PROVISIONED", "version": "1.0",
            "ibx": "DC1", "metroCode": "DC", "redundancyType": "PRIMARY",
            "sshIpAddress": "192.0.2.50",
            "vendorConfig": {"adminPassword": "[redacted]"},
            "interfaces": [
                {"id": 1, "name": "eth0", "type": "DATA", "uuid": FW_ETH0, "macAddress": FW_MAC},
                interface(2, "eth1", None),
                interface(3, "eth2", Some("00:00:5e:00:53:35")),
                {"id": 8, "name": "eth7", "type": "SSH"},
            ],
        },
        {
            "uuid": RTR, "name": "lab-rtr", "deviceTypeCode": "C8000V",
            "deviceTypeVendor": "Cisco", "deviceTypeCategory": "ROUTER",
            "status": "PROVISIONED",
            "interfaces": [
                interface(6, "GigabitEthernet6", Some("00:00:5e:00:53:32")),
                interface(7, "GigabitEthernet7", Some("00:00:5e:00:53:33")),
                interface(8, "GigabitEthernet8", None),
            ],
        },
        {
            "uuid": HUB, "name": "lab-hub", "deviceTypeCode": "C8000V",
            "status": "PROVISIONED",
            "interfaces": [
                interface(2, "GigabitEthernet0/2", Some("00:00:5e:00:53:34")),
                interface(3, "GigabitEthernet0/3", None),
                interface(4, "GigabitEthernet0/4", None),
            ],
        },
    ])
}

fn member(device: &str, id: i64) -> Value {
    json!({"deviceUuid": device, "interfaceId": id, "status": "PROVISIONED"})
}

fn edge_links() -> Value {
    json!([
        {"uuid": "g-pair", "groupName": "lab-pair", "status": "PROVISIONED",
         "metroLinks": [], "linkDevices": [member(HUB, 2), member(RTR, 6)]},
        {"uuid": "g-four", "groupName": "lab-four", "status": "PROVISIONED",
         "metroLinks": [
             {"metroCode": "DC", "throughput": "500", "throughputUnit": "MBPS"},
             {"metroCode": "SV", "throughput": "200", "throughputUnit": "Mbps"},
             {"metroCode": "NY", "throughput": "1", "throughputUnit": "Gbps"},
         ],
         "linkDevices": [member(RTR, 7), member(FW, 2), member(HUB, 3),
                         member("not-in-the-account", 1)]},
        {"uuid": "g-pending", "groupName": "lab-pending", "status": "PROVISIONING",
         "linkDevices": [member(FW, 3), member(RTR, 99)]},
        {"uuid": "g-shared", "groupName": "lab-shared", "status": "PROVISIONED",
         "linkDevices": [member(RTR, 8), member(HUB, 4)]},
    ])
}

fn port() -> Value {
    json!([{"uuid": "p1", "name": "lab-p1", "state": "ACTIVE",
            "encapsulation": {"type": "DOT1Q"}}])
}

fn vd(device: &str, interface: Value) -> Value {
    json!({"accessPoint": {"type": "VD", "interface": interface,
           "virtualDevice": {"uuid": device, "name": "x", "type": "EDGE"}}})
}

fn colo(tag: i64) -> Value {
    json!({"accessPoint": {"type": "COLO", "port": {"uuid": "p1"},
           "linkProtocol": {"type": "DOT1Q", "vlanTag": tag}}})
}

fn circuit(uuid: &str, a: Value, z: Value) -> Value {
    json!({"uuid": uuid, "type": "EVPL_VC", "state": "ACTIVE", "aSide": a, "zSide": z})
}

fn edge_connections() -> Value {
    let mut proto = vd(FW, json!({"id": 8}));
    proto["accessPoint"]["linkProtocol"] = json!({"type": "DOT1Q", "vlanTag": 5});
    json!([
        circuit(
            "c-ne",
            vd(FW, json!({"uuid": FW_ETH0, "id": 1, "type": "CLOUD"})),
            colo(830)
        ),
        circuit(
            "c-foreign",
            vd("eeeeeeee-0000-4000-8000-000000000009", json!({"id": 1})),
            colo(840)
        ),
        circuit("c-proto", proto, colo(850)),
        circuit("c-group", colo(860), vd(RTR, json!({"id": 8}))),
        circuit("c-noif", vd(HUB, json!({"id": 42})), colo(870)),
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

fn account(bindings: Value) -> equinix::Account {
    let p = Parsed::new(&sections(&[
        ("ports", port()),
        ("connections", json!([])),
        ("edge_devices", edge_devices()),
        ("edge_links", edge_links()),
        ("edge_connections", edge_connections()),
        ("bindings", bindings),
    ]));
    equinix::read(ACCT, &p)
}

fn lowered(peers: &BTreeMap<String, FunctionId>) -> Lowered {
    equinix::lower(&account(json!([])), &equinix::profile(), peers)
}

fn ids(l: &Lowered) -> Vec<String> {
    l.functions.iter().map(|f| f.id().to_string()).collect()
}

fn verdict(l: &Lowered, uuid: &str) -> Verdict {
    l.circuits
        .iter()
        .find(|c| c.uuid == uuid)
        .unwrap_or_else(|| panic!("{uuid} is not in the rows"))
        .verdict
        .clone()
}

fn fid(s: &str) -> FunctionId {
    FunctionId::new(s)
}

#[test]
fn the_reader_gives_the_devices_the_interfaces_and_the_link_groups() {
    let a = account(json!([]));
    assert_eq!(a.edge_devices.len(), 3);
    let fw = &a.edge_devices[0];
    assert_eq!(fw.name, "lab-fw");
    assert_eq!(fw.model.as_deref(), Some("FW-CODE"));
    let names: Vec<&str> = fw.interfaces.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["eth0", "eth1", "eth2", "eth7"]);
    assert_eq!(fw.interfaces[0].mac, Some(FW_MAC.parse::<Mac>().unwrap()));
    assert_eq!(fw.interfaces[0].id.as_deref(), Some("1"));
    let four = a.link_groups.iter().find(|g| g.uuid == "g-four").unwrap();
    assert_eq!(four.members.len(), 4);
    assert_eq!(four.bandwidth_mbps, Some(200));
    let pair = a.link_groups.iter().find(|g| g.uuid == "g-pair").unwrap();
    assert_eq!(pair.bandwidth_mbps, None);
}

#[test]
fn a_vd_end_with_no_link_protocol_joins_the_tag_of_the_fabric_end_to_the_untagged_interface() {
    let peers = BTreeMap::from([
        ("port/p1".to_string(), fid("sw-a/port/Ethernet1/49/in")),
        (format!("ne-{FW}/1"), fid("fw-x/eth0/in")),
    ]);
    let l = lowered(&peers);
    assert_eq!(verdict(&l, "c-ne"), Verdict::Lowered);
    let port = format!("ne-{FW}/1");
    let leg = l.ports["p1"]
        .legs
        .iter()
        .find(|g| g.circuit == "c-ne")
        .unwrap();
    assert_eq!(leg.near.outer.vlan, 830);
    match &leg.far {
        FarEnd::Port {
            port: p,
            tags,
            peer,
        } => {
            assert_eq!(p.to_string(), port);
            assert_eq!(tags.outer.vlan, 830);
            assert_eq!(peer.to_string(), format!("{ACCT}/{port}/out"));
        }
        FarEnd::Sink(s) => panic!("the far end is the sink {s}"),
    }
    let ids = ids(&l);
    for f in ["in", "circuit", "out"] {
        assert!(ids.contains(&format!("{ACCT}/{port}/{f}")), "{f}: {ids:#?}");
    }
    assert!(l.edge_ports.contains_key(&port));
}

#[test]
fn a_vd_end_that_the_twin_does_not_follow_is_unknown_with_its_reason() {
    let l = lowered(&BTreeMap::new());
    for (c, r) in [
        ("c-foreign", "the far end is outside the account"),
        (
            "c-proto",
            "the link protocol DOT1Q on the Network Edge device lab-fw is not handled",
        ),
        (
            "c-noif",
            "the end names no interface of the Network Edge device lab-hub",
        ),
        (
            "c-group",
            "the Network Edge interface lab-rtr GigabitEthernet8 is in more than one circuit or device link group",
        ),
    ] {
        assert_eq!(verdict(&l, c), Verdict::Unknown(r.to_string()), "{c}");
    }
}

#[test]
fn without_the_network_edge_sections_a_vd_end_is_unknown() {
    let p = Parsed::new(&sections(&[
        ("ports", port()),
        ("connections", edge_connections()),
    ]));
    let a = equinix::read(ACCT, &p);
    let l = equinix::lower(&a, &equinix::profile(), &BTreeMap::new());
    assert_eq!(
        verdict(&l, "c-ne"),
        Verdict::Unknown("the Network Edge devices of the account are not collected".to_string())
    );
}

#[test]
fn a_device_link_group_is_a_bridge_domain_with_a_mac_lookup_and_a_flood() {
    let l = lowered(&BTreeMap::new());
    let ids = ids(&l);
    for g in ["g-pair", "g-four"] {
        for f in ["mac", "unknown", "flood"] {
            assert!(
                ids.contains(&format!("{ACCT}/link-group/{g}/{f}")),
                "{g} {f}: {ids:#?}"
            );
        }
    }
    for port in [format!("ne-{HUB}/2"), format!("ne-{RTR}/6")] {
        for f in ["in", "ingress", "out"] {
            assert!(ids.contains(&format!("{ACCT}/{port}/{f}")), "{port} {f}");
        }
    }
    assert!(
        ids.contains(&format!(
            "{ACCT}/link-group/g-four/outside/ne-not-in-the-account/1"
        )),
        "{ids:#?}"
    );
}

#[test]
fn a_device_link_group_whose_state_is_not_handled_is_unknown_at_each_member() {
    let l = lowered(&BTreeMap::new());
    let ids = ids(&l);
    let port = format!("ne-{FW}/3");
    assert!(ids.contains(&format!("{ACCT}/{port}/in")));
    assert!(!ids.contains(&format!("{ACCT}/{port}/ingress")));
    assert!(!ids.iter().any(|f| f.contains("link-group/g-pending/")));
}

#[test]
fn a_member_of_a_group_and_a_circuit_makes_both_unknown() {
    let l = lowered(&BTreeMap::new());
    let ids = ids(&l);
    assert!(!ids.iter().any(|f| f.contains("link-group/g-shared/")));
    assert!(ids.contains(&format!("{ACCT}/ne-{RTR}/8/in")));
    assert!(ids.contains(&format!("{ACCT}/ne-{HUB}/4/in")));
}

#[test]
fn each_function_of_the_account_has_its_own_id() {
    let l = lowered(&BTreeMap::new());
    let ids = ids(&l);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "{ids:#?}");
}

#[test]
fn a_network_edge_device_with_no_binding_is_a_twin_device_whose_ports_are_unknown() {
    let l = lowered(&BTreeMap::new());
    let ids = ids(&l);
    let twin = format!("{ACCT}-ne-{FW}");
    assert!(ids.contains(&format!("{twin}/eth0/in")), "{ids:#?}");
    let s = equinix::summary(&account(json!([])));
    let b = s
        .account
        .bindings
        .iter()
        .find(|b| b.port == format!("ne-{FW}/1"))
        .expect("the binding to the twin device");
    assert_eq!(
        (b.device.as_str(), b.far_port.as_str()),
        (twin.as_str(), "eth0")
    );
    assert!(s.devices[&twin].entries.contains_key("eth0"));
    assert!(s.macs.is_empty());
}

#[test]
fn a_binding_names_a_device_by_its_uuid_or_its_name_in_any_case() {
    let a = account(json!([
        {"edge_device": FW.to_uppercase(), "device": "fw-a"},
        {"edge_device": "LAB-RTR", "device": "rtr-a"},
        {"edge_device": "lab-hub-missing", "device": "hub-a"},
    ]));
    let (bound, notes) = equinix::edge::bound(&a);
    assert_eq!(
        bound,
        BTreeMap::from([
            (FW.to_string(), "fw-a".to_string()),
            (RTR.to_string(), "rtr-a".to_string()),
        ])
    );
    assert_eq!(
        notes,
        ["the binding of lab-hub-missing names no Network Edge device of the account"]
    );
    let s = equinix::summary(&a);
    assert!(!s.devices.contains_key(&format!("{ACCT}-ne-{FW}")));
    let m = s
        .macs
        .iter()
        .find(|m| m.port == format!("ne-{FW}/1"))
        .unwrap();
    assert_eq!(m.device, "fw-a");
    assert_eq!(m.mac, Some(FW_MAC.parse().unwrap()));
}

#[test]
fn two_network_edge_devices_bound_to_one_device_give_a_note() {
    let a = account(json!([
        {"edge_device": FW, "device": "box"},
        {"edge_device": "lab-rtr", "device": "box"},
    ]));
    let (_, notes) = equinix::edge::bound(&a);
    assert_eq!(
        notes,
        ["the Network Edge devices lab-rtr, lab-fw are bound to one device box"]
    );
}

#[test]
fn a_bound_interface_binds_to_the_one_port_with_its_mac() {
    let a = account(json!([{"edge_device": FW, "device": "fw-a"}]));
    let s = equinix::summary(&a);
    let eth0: Vec<equinix::MacBinding> = s
        .macs
        .iter()
        .filter(|m| m.port == format!("ne-{FW}/1"))
        .cloned()
        .collect();
    let mac: Mac = FW_MAC.parse().unwrap();
    let with = |ports: &[&str]| {
        let mut sum = Summary::default();
        for p in ports {
            sum.port_macs.insert((*p).to_string(), mac);
        }
        BTreeMap::from([("fw-a".to_string(), sum)])
    };
    let (b, notes) = equinix::mac_bindings(&eth0, &with(&["ge-0/0/0"]));
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(b.len(), 1);
    assert_eq!(
        (b[0].port.as_str(), b[0].far_port.as_str()),
        (format!("ne-{FW}/1").as_str(), "ge-0/0/0")
    );
    let (b, notes) = equinix::mac_bindings(&eth0, &with(&[]));
    assert!(b.is_empty());
    assert_eq!(
        notes,
        [format!(
            "no port of fw-a has the MAC {FW_MAC} of the Network Edge interface lab-fw eth0"
        )]
    );
    let (b, notes) = equinix::mac_bindings(&eth0, &with(&["ge-0/0/0", "ge-0/0/1"]));
    assert!(b.is_empty());
    assert_eq!(
        notes,
        [format!(
            "2 ports of fw-a have the MAC {FW_MAC} of the Network Edge interface lab-fw eth0"
        )]
    );
}

#[test]
fn each_path_of_the_network_edge_sections_is_classified() {
    let p = Parsed::new(&sections(&[
        ("edge_devices", edge_devices()),
        ("edge_links", edge_links()),
        ("edge_connections", edge_connections()),
        ("bindings", json!([{"edge_device": FW, "device": "fw-a"}])),
    ]));
    let cov = equinix::coverage::classify(&p);
    assert!(cov.unhandled.is_empty(), "{:#?}", cov.unhandled);
}
