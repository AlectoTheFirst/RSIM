//! The VeloCloud reader on synthetic sections: the effective configuration,
//! the hub references, the WAN links, the rule reader, the overlay rows,
//! the route order, the BGP sessions, the facts, the coverage and the mask.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_core::Prefix;
use rsim_ingest::coverage::State;
use rsim_ingest::facts::{Fact, Reason, Sections, device};
use rsim_ingest::mask::section_lines;
use rsim_ingest::velocloud::reader::{
    Enterprise, HubRole, InterfaceKind, KindSource, LinkKind, Modules, Peers, SessionSegment,
};
use rsim_ingest::velocloud::routes::{Counts, DynamicKind, ExitKind, RouteClass, order};
use rsim_ingest::velocloud::rules::{
    AddrEntry, AddrMatch, Business, Firewall, FirewallAction, IpVersion, LinkPolicy, Match,
    ObjectGroups, Policy, PortMatch, PortRange, RoutePolicy, Rule, Target, Word, read_match,
};
use rsim_ingest::velocloud::{Parsed, coverage, read};
use rsim_store::Format;
use serde_json::{Value, json};

const STORE: &str = "vco-orch1-ent-1";

const SECTIONS: &[&str] = &[
    "aggregates",
    "bgp_sessions",
    "edge_modules",
    "edges",
    "object_groups",
    "profiles",
    "route_table",
    "sdwan_peers",
];

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/velocloud/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn fixture(name: &str) -> Value {
    serde_json::from_slice(&fixture_bytes(name)).unwrap()
}

/// The sections of the fixtures; `edge_state` has the bytes of `edges`.
fn base() -> BTreeMap<String, Value> {
    let mut m: BTreeMap<String, Value> = SECTIONS
        .iter()
        .map(|s| (s.to_string(), fixture(s)))
        .collect();
    m.insert("edge_state".into(), fixture("edges"));
    m
}

fn parsed(m: &BTreeMap<String, Value>) -> Parsed {
    let raw: BTreeMap<String, (Vec<u8>, String)> = m
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                (serde_json::to_vec(v).unwrap(), format!("{STORE}/{k}@b1")),
            )
        })
        .collect();
    Parsed::new(&raw)
}

fn ent(m: &BTreeMap<String, Value>) -> Enterprise {
    read(STORE, "ent-1", &parsed(m), &["OurNet".to_string()])
}

fn firewall_of(p: &Policy<Firewall>) -> &Firewall {
    match p {
        Policy::Read(f) => f,
        Policy::NotRead(r) => panic!("{r}"),
    }
}

fn business_of(p: &Policy<Business>) -> &Business {
    match p {
        Policy::Read(b) => b,
        Policy::NotRead(r) => panic!("{r}"),
    }
}

fn ids<A>(rules: &[Rule<A>]) -> Vec<&str> {
    rules.iter().map(|r| r.id.as_str()).collect()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn pfx(s: &str) -> Prefix {
    s.parse().unwrap()
}

/// The match of one JSON object.
fn matched(m: Value, groups: &ObjectGroups) -> Match {
    let raw = BTreeMap::from([(
        "m".to_string(),
        (serde_json::to_vec(&m).unwrap(), "m@b1".to_string()),
    )]);
    let p = Parsed::new(&raw);
    read_match(p.root("m"), groups)
}

fn bound_keys(m: &Match) -> Vec<&str> {
    m.bounds.iter().map(|b| b.key.as_str()).collect()
}

#[test]
fn the_effective_configuration_merges_the_profile_with_the_edge_data() {
    let e = ent(&base());
    assert_eq!(e.numeric_id, Some(1));
    assert_eq!(e.name.as_deref(), Some("Example One"));
    let segs: Vec<(u32, &str, bool)> = e
        .segments
        .iter()
        .map(|s| (s.id, s.name.as_str(), s.global))
        .collect();
    assert_eq!(segs, [(0, "Global Segment", true), (1, "corp", false)]);
    let br = e.edge("e-br").unwrap();
    assert_eq!(br.device, "vco-orch1-ent-1/edge/e-br");
    assert_eq!(br.settings_unknown, None);
    assert_eq!(br.segments.len(), 2);
    let global = br.segments[0].bgp.as_ref().unwrap();
    assert_eq!(global.neighbours[0].address, ip("10.255.0.9"));
    assert_eq!(global.neighbours[0].asn, None);
    assert!(
        br.notes.iter().any(|n| n.contains("10.255.0.9")),
        "{:?}",
        br.notes
    );
    let corp = br.segments[1].bgp.as_ref().unwrap();
    assert_eq!(corp.router_id, Some(ip("10.9.9.1")));
    assert_eq!(corp.asn, Some(65010));
    assert_eq!(corp.neighbours.len(), 1);
    assert_eq!(corp.neighbours[0].address, ip("10.9.9.2"));
    assert_eq!(corp.neighbours[0].asn, Some(65000));
    let ifs: Vec<(&str, bool, Option<u32>)> = br
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i.wan, i.segment))
        .collect();
    assert_eq!(
        ifs,
        [
            ("GE1", true, None),
            ("GE3", false, Some(1)),
            ("GE3:10", false, Some(1)),
            ("LO1", false, Some(1)),
            ("users", false, Some(1)),
        ]
    );
    assert_eq!(br.interfaces[0].address, Some((ip("172.16.1.2"), 30)));
    assert_eq!(br.interfaces[0].gateway, Some(ip("172.16.1.1")));
    assert_eq!(
        br.interfaces[2].kind,
        InterfaceKind::Sub {
            parent: "GE3".into(),
            id: 10
        }
    );
    assert_eq!(br.interfaces[2].vlan, Some(110));
    assert_eq!(br.interfaces[4].vlan, Some(10));
}

#[test]
fn a_hub_reference_names_the_members_of_its_cluster() {
    let e = ent(&base());
    assert_eq!(e.clusters.len(), 1);
    assert_eq!(e.clusters[0].id, "cl-dc");
    assert_eq!(e.clusters[0].name.as_deref(), Some("DC-CLUSTER"));
    assert_eq!(e.clusters[0].members, ["e-hub"]);
    let br = e.edge("e-br").unwrap();
    let hub = e.edge("e-hub").unwrap();
    assert!(!br.hub);
    assert!(hub.hub);
    assert_eq!(hub.cluster.as_deref(), Some("cl-dc"));
    let refs = &br.segments[0].hubs;
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].role, HubRole::Vpn);
    assert_eq!(refs[0].cluster.as_deref(), Some("cl-dc"));
    assert_eq!(refs[0].edges, ["e-hub"]);
    assert_eq!(br.segments[1].data_center.len(), 1);
    assert_eq!(br.segments[1].data_center[0].edge.as_deref(), Some("e-hub"));

    let mut m = base();
    m.get_mut("edges").unwrap()[1]["isHub"] = json!(false);
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
    assert!(ent(&m).edge("e-hub").unwrap().hub);
}

#[test]
fn a_cluster_name_with_no_named_cluster_names_no_hub() {
    let mut m = base();
    let modules = m.get_mut("edge_modules").unwrap();
    modules["e-hub"]["controlPlane"]["data"]
        .as_object_mut()
        .unwrap()
        .remove("memberCluster");
    modules["e-br"]["controlPlane"]["data"]["segments"] = json!([]);
    let e = ent(&m);
    assert!(e.clusters.is_empty());
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(hub.cluster, None);
    assert_eq!(hub.ha.cluster_name.as_deref(), Some("DC-CLUSTER"));
    assert!(hub.hub);
    let br = e.edge("e-br").unwrap();
    assert!(br.segments[0].hubs[0].edges.is_empty());
}

/// The backhaul hubs of the rule `rule-backup` of `e-br`.
fn backhaul(e: &Enterprise) -> Vec<(Option<String>, Vec<String>, Option<usize>)> {
    let rules = &business_of(&e.edge("e-br").unwrap().business).segments[0].rules;
    rules[3].action.routes[1]
        .backhaul
        .iter()
        .map(|h| (h.name.clone(), h.edges.clone(), h.shared_name))
        .collect()
}

#[test]
fn a_hub_name_of_more_than_one_edge_or_cluster_names_no_hub() {
    let mut m = base();
    m.get_mut("edges").unwrap()[0]["name"] = json!("hub-1");
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
    let e = ent(&m);
    assert_eq!(
        backhaul(&e),
        [
            (
                Some("DC-CLUSTER".to_string()),
                vec!["e-hub".to_string()],
                None
            ),
            (Some("hub-1".to_string()), Vec::new(), Some(2)),
        ]
    );
    let br = e.edge("e-br").unwrap();
    assert!(
        br.notes
            .iter()
            .any(|n| n == "hub reference hub-1: 2 hubs with the name"),
        "{:?}",
        br.notes
    );

    let mut m = base();
    m.get_mut("edge_modules").unwrap()["e-br"]["controlPlane"]["data"]["segments"][0]["vpn"]
        ["dataCenterEdges"]
        .as_array_mut()
        .unwrap()
        .push(json!({"clusterLogicalId": "cl-dc2", "clusterName": "DC-CLUSTER"}));
    let e = ent(&m);
    assert_eq!(e.clusters.len(), 2);
    assert_eq!(e.clusters[0].members, ["e-hub"]);
    assert!(e.clusters[1].members.is_empty());
    assert_eq!(
        backhaul(&e),
        [
            (Some("DC-CLUSTER".to_string()), Vec::new(), Some(2)),
            (Some("hub-1".to_string()), vec!["e-hub".to_string()], None),
        ]
    );
    let vpn = &e.edge("e-br").unwrap().segments[0].hubs[0];
    assert_eq!(vpn.cluster.as_deref(), Some("cl-dc"));
    assert_eq!(vpn.edges, ["e-hub"]);
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(hub.cluster.as_deref(), Some("cl-dc"));
    assert!(
        hub.notes
            .iter()
            .any(|n| n == "cluster name DC-CLUSTER: 2 clusters"),
        "{:?}",
        hub.notes
    );
}

#[test]
fn the_ha_facts_the_module_state_and_the_peers_of_each_edge() {
    let e = ent(&base());
    let br = e.edge("e-br").unwrap();
    assert_eq!(br.state.as_deref(), Some("CONNECTED"));
    assert_eq!(br.ha.kind.as_deref(), Some("ACTIVE_STANDBY"));
    assert_eq!(br.ha.state.as_deref(), Some("READY"));
    assert_eq!(br.ha.standby_serial.as_deref(), Some("S-e-br-standby"));
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(hub.ha.kind.as_deref(), Some("ACTIVE_ACTIVE"));
    assert_eq!(hub.ha.state, None);
    assert_eq!(hub.ha.standby_serial, None);
    assert_eq!(br.modules, Modules::Read { stale: false });
    assert_eq!(hub.modules, Modules::Read { stale: true });
    match &br.peers {
        Peers::Read(p) => {
            assert_eq!(p.len(), 2);
            assert_eq!(p[0].logical_id.as_deref(), Some("e-hub"));
            assert_eq!(p[0].kind.as_deref(), Some("HUB"));
            assert_eq!(p[0].paths.stable, Some(2));
            assert_eq!(p[1].logical_id.as_deref(), Some("g-1"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(hub.peers, Peers::Gap("getEdgeSDWANPeers: 403".into()));
}

#[test]
fn the_wan_links_take_their_kind_from_the_wan_module() {
    let e = ent(&base());
    let br = e.edge("e-br").unwrap();
    let lids: Vec<&str> = br.links.iter().map(|l| l.logical_id.as_str()).collect();
    assert_eq!(lids, ["l-br-dia", "l-br-mpls"]);
    let dia = &br.links[0];
    assert_eq!(dia.kind, LinkKind::Public { wireless: false });
    assert_eq!(dia.kind_from, KindSource::WanModule);
    assert_eq!(dia.address, Some(ip("198.51.100.2")));
    assert_eq!(dia.local, None);
    assert_eq!(dia.gateway, Some(ip("198.51.100.1")));
    let mpls = &br.links[1];
    assert_eq!(
        mpls.kind,
        LinkKind::Private {
            network: Some("MPLS-A".into())
        }
    );
    assert_eq!(mpls.interface.as_deref(), Some("GE1"));
    assert_eq!(mpls.local, Some(ip("172.16.1.2")));
    assert_eq!(mpls.gateway, Some(ip("172.16.1.1")));
    assert_eq!(mpls.state.as_deref(), Some("STABLE"));
    assert_eq!(mpls.ambiguous, None);
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(hub.links[0].kind, LinkKind::Public { wireless: true });
    assert_eq!(br.gateways.len(), 1);
    assert_eq!(br.gateways[0].id, "g-1");
    assert_eq!(br.gateways[0].address, Some(ip("192.0.2.10")));
    assert_eq!(br.gateways[0].segments, [0, 1]);
}

#[test]
fn listing_rows_of_one_link_with_no_internal_id_of_the_wan_module_give_an_unknown_link() {
    let mut m = base();
    let edges = m.get_mut("edges").unwrap();
    let mut old = edges[0]["links"][1].clone();
    old["internalId"] = json!("int-old");
    old["ipAddress"] = json!("198.51.100.66");
    edges[0]["links"].as_array_mut().unwrap().push(old);
    let edges = m["edges"].clone();
    m.insert("edge_state".into(), edges);
    let e = ent(&m);
    let dia = &e.edge("e-br").unwrap().links[0];
    assert_eq!(dia.ambiguous, None);
    assert_eq!(dia.address, Some(ip("198.51.100.2")));

    m.get_mut("edge_modules").unwrap()["e-br"]["WAN"]["data"]["links"][1]
        .as_object_mut()
        .unwrap()
        .remove("internalId");
    let e = ent(&m);
    let br = e.edge("e-br").unwrap();
    let dia = &br.links[0];
    assert_eq!(dia.logical_id, "l-br-dia");
    assert_eq!(dia.ambiguous, Some(2));
    assert_eq!(dia.address, None);
    assert_eq!(dia.state, None);
    assert_eq!(dia.kind, LinkKind::Public { wireless: false });
    assert!(
        br.notes
            .iter()
            .any(|n| n.starts_with("link l-br-dia: 2 listing rows")),
        "{:?}",
        br.notes
    );
}

#[test]
fn a_private_carrier_name_applies_only_to_a_link_with_no_wan_module_row() {
    let mut m = base();
    m.get_mut("edge_modules").unwrap()["e-br"]
        .as_object_mut()
        .unwrap()
        .remove("WAN");
    let e = ent(&m);
    let br = e.edge("e-br").unwrap();
    assert_eq!(br.links[1].kind, LinkKind::Private { network: None });
    assert_eq!(br.links[1].kind_from, KindSource::CarrierName);
    assert_eq!(br.links[0].kind, LinkKind::NotKnown);
    assert_eq!(br.links[0].kind_from, KindSource::NotKnown);

    let carriers = ["ThirdParty ISP".to_string(), "OurNet".to_string()];
    let e = read(STORE, "ent-1", &parsed(&base()), &carriers);
    let br = e.edge("e-br").unwrap();
    assert_eq!(br.links[0].kind, LinkKind::Public { wireless: false });
    assert_eq!(br.links[0].kind_from, KindSource::WanModule);
}

#[test]
fn the_edge_rules_come_first_and_a_repeated_rule_id_replaces_only_its_rule() {
    let e = ent(&base());
    let br = e.edge("e-br").unwrap();
    let b = business_of(&br.business);
    assert_eq!(b.segments.len(), 1);
    assert_eq!(b.segments[0].segment, Some(1));
    let rules = &b.segments[0].rules;
    assert_eq!(
        ids(rules),
        [
            "rule-mgmt",
            "rule-web",
            "rule-voice",
            "rule-backup",
            "d-any"
        ]
    );
    assert_eq!(rules[1].name.as_deref(), Some("web-edge"));
    let edge: Vec<bool> = rules.iter().map(|r| r.from_edge).collect();
    assert_eq!(edge, [true, true, false, false, false]);
    assert!(rules[4].default);
    let fw = firewall_of(&br.firewall);
    assert_eq!(fw.enabled, Some(true));
    assert_eq!(fw.stateful, Some(true));
    assert_eq!(fw.segments[0].stateful, Some(true));
    let out = &fw.segments[0].rules;
    assert_eq!(ids(out), ["fw-mgmt", "fw-block-guest", "fw-dns", "fw-chat"]);
    assert_eq!(out[1].action, FirewallAction::Reject);
    assert_eq!(out[2].action, FirewallAction::Allow);
    assert_eq!(out[3].action, FirewallAction::Skip);
    assert_eq!(bound_keys(&out[3].matches), ["appid"]);
    assert_eq!(fw.inbound.len(), 1);
    assert_eq!(fw.inbound[0].action.lan_ip, Some(ip("10.10.10.20")));
    assert_eq!(fw.inbound[0].action.lan_port, Some(8443));
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(
        ids(&business_of(&hub.business).segments[0].rules),
        ["rule-web", "d-any"]
    );
    assert_eq!(hub.firewall, Policy::NotRead("no firewall module".into()));
}

#[test]
fn a_refused_profile_read_leaves_the_profile_part_of_each_policy_unknown() {
    let mut m = base();
    m.remove("profiles");
    let e = ent(&m);
    assert_eq!(e.edges.len(), 2);
    let br = e.edge("e-br").unwrap();
    assert_eq!(
        br.settings_unknown.as_deref(),
        Some("profiles not collected")
    );
    let b = business_of(&br.business);
    assert_eq!(ids(&b.segments[0].rules), ["rule-mgmt", "rule-web"]);
    assert_eq!(b.unknown_tail.as_deref(), Some("profiles not collected"));
    assert_eq!(
        b.segments[0].unknown_tail.as_deref(),
        Some("profiles not collected")
    );
    let fw = firewall_of(&br.firewall);
    assert_eq!(ids(&fw.segments[0].rules), ["fw-mgmt", "fw-block-guest"]);
    assert_eq!(fw.unknown_tail.as_deref(), Some("profiles not collected"));
    let hub = e.edge("e-hub").unwrap();
    assert_eq!(
        hub.business,
        Policy::NotRead("profiles not collected".into())
    );
}

#[test]
fn a_rule_gives_exact_predicates_and_its_action_as_read() {
    let e = ent(&base());
    let br = e.edge("e-br").unwrap();
    let rules = &business_of(&br.business).segments[0].rules;
    let voice = &rules[2];
    let m = &voice.matches;
    assert_eq!(m.ip_version, Some(IpVersion::V4));
    assert_eq!(m.source, AddrMatch::Any);
    assert_eq!(
        m.destination,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("10.20.0.0/16"))])
    );
    assert_eq!(m.protocol, Some(17));
    assert_eq!(m.dscp, Some(46));
    assert_eq!(m.source_ports, PortMatch::Any);
    assert_eq!(
        m.destination_ports,
        PortMatch::Set(vec![PortRange {
            protocol: None,
            low: 5060,
            high: 5061
        }])
    );
    assert!(m.bounds.is_empty(), "{:?}", m.bounds);
    let a = &voice.action;
    assert_eq!(a.route_type.as_deref(), Some("edge2Any"));
    assert!(!a.nat);
    let q = a.qos.as_ref().unwrap();
    assert_eq!(q.class.as_deref(), Some("realtime"));
    assert_eq!(q.priority_tx.as_deref(), Some("high"));
    assert_eq!((q.cap_tx, q.cap_rx), (None, Some(20)));
    assert_eq!(a.routes.len(), 1);
    let r = &a.routes[0];
    assert_eq!(r.target, Target::Edge);
    assert_eq!(r.route_policy, Word::Known(RoutePolicy::Auto));
    assert_eq!(r.link_policy, Word::Known(LinkPolicy::Fixed));
    assert_eq!(r.wanlink.as_deref(), Some("l-br-mpls"));
    assert_eq!(r.outer_dscp, Word::Known(46));

    let backup = &rules[3];
    assert_eq!(backup.matches.ip_version, Some(IpVersion::V6));
    assert_eq!(
        backup.matches.destination_v6,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("2001:db8:30::/48"))])
    );
    let targets: Vec<Target> = backup.action.routes.iter().map(|r| r.target).collect();
    assert_eq!(targets, [Target::Edge, Target::Cloud]);
    assert_eq!(
        backup.action.routes[0].route_policy,
        Word::Known(RoutePolicy::Gateway)
    );
    assert_eq!(
        backup.action.routes[0].link_policy,
        Word::Other("mystery".into())
    );
    let cloud = &backup.action.routes[1];
    assert_eq!(cloud.route_policy, Word::Known(RoutePolicy::Backhaul));
    assert_eq!(cloud.link_policy, Word::Known(LinkPolicy::Private));
    assert_eq!(cloud.outer_dscp, Word::Known(0));
    assert_eq!(cloud.inner_dscp, Word::NotStated);
    assert_eq!(cloud.service_group.as_deref(), Some("ALL"));
    let hubs: Vec<(Option<&str>, Vec<String>)> = cloud
        .backhaul
        .iter()
        .map(|h| (h.name.as_deref(), h.edges.clone()))
        .collect();
    assert_eq!(
        hubs,
        [
            (Some("DC-CLUSTER"), vec!["e-hub".to_string()]),
            (Some("hub-1"), vec!["e-hub".to_string()]),
        ]
    );
    assert!(cloud.backhaul.iter().all(|h| h.role == HubRole::Backhaul));
}

#[test]
fn an_address_group_and_a_port_group_give_their_entries() {
    let e = ent(&base());
    let hub = e.edge("e-hub").unwrap();
    let web = &business_of(&hub.business).segments[0].rules[0];
    let m = &web.matches;
    assert_eq!(
        m.source,
        AddrMatch::Set(vec![
            AddrEntry::Prefix(pfx("10.10.10.0/24")),
            AddrEntry::Prefix(pfx("10.11.0.0/16")),
            AddrEntry::Wildcard {
                addr: ip("10.12.0.1"),
                wildcard: ip("0.255.0.255")
            },
        ])
    );
    assert_eq!(
        m.source_v6,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("2001:db8:10::/48"))])
    );
    assert_eq!(
        m.destination_ports,
        PortMatch::Set(vec![
            PortRange {
                protocol: Some(6),
                low: 80,
                high: 80
            },
            PortRange {
                protocol: Some(6),
                low: 443,
                high: 443
            },
        ])
    );
    assert_eq!(bound_keys(m), ["appid"]);

    let m = matched(
        json!({"sAddressGroup": "grp-domains", "dAddressGroup": "grp-none"}),
        &e.object_groups,
    );
    assert_eq!(m.source, AddrMatch::Any);
    assert_eq!(m.destination, AddrMatch::Any);
    assert_eq!(bound_keys(&m), ["dAddressGroup", "sAddressGroup"]);
}

#[test]
fn open_values_leave_a_field_open_and_each_key_that_is_not_exact_is_a_bound() {
    let groups = ObjectGroups::default();
    let m = matched(
        json!({"sip": "any", "dip": "", "proto": -1, "sport_low": -1, "dscp": -1,
               "appid": -1, "hostname": "", "sInterface": "any", "svlan": -1}),
        &groups,
    );
    assert_eq!(m, Match::default());

    let m = matched(json!({"sip": "10.1.2.3"}), &groups);
    assert_eq!(
        m.source,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("10.1.2.3/32"))])
    );
    let m = matched(
        json!({"sip": "10.1.2.0", "ssm": "255.255.255.0", "s_rule_type": "exact"}),
        &groups,
    );
    assert_eq!(
        m.source,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("10.1.2.0/32"))])
    );

    let m = matched(
        json!({"ipVersion": "IPv6", "dip": "10.0.0.0", "dsm": "255.0.0.0"}),
        &groups,
    );
    assert_eq!(bound_keys(&m), ["ipVersion"]);

    let m = matched(
        json!({"sAddressGroup": "grp-1", "dip": "10.0.0.0", "sPortGroup": "", "x": -1,
               "smac": "00:00:5e:00:53:01", "os_version": 2, "dInterface": "GE3", "dvlan": 20,
               "classid": 4, "sip_prenat_enabled": 0, "dip_prenat_enabled": 1,
               "proto": "tcp", "zone": "trusted"}),
        &groups,
    );
    let mut want = [
        "sAddressGroup",
        "smac",
        "os_version",
        "dInterface",
        "dvlan",
        "classid",
        "dip_prenat_enabled",
        "proto",
        "zone",
    ];
    want.sort_unstable();
    assert_eq!(bound_keys(&m), want);
    assert_eq!(
        m.destination,
        AddrMatch::Set(vec![AddrEntry::Prefix(pfx("10.0.0.0/32"))])
    );
    assert_eq!(m.protocol, None);
}

#[test]
fn a_rule_with_no_id_takes_its_place_in_its_own_list() {
    let mut m = base();
    m.get_mut("profiles").unwrap()[1]["modules"][1]["data"]["segments"][0]["defaults"][0]
        .as_object_mut()
        .unwrap()
        .remove("ruleLogicalId");
    let hub_ids = |e: &Enterprise| -> Vec<String> {
        let b = business_of(&e.edge("e-hub").unwrap().business);
        ids(&b.segments[0].rules)
            .into_iter()
            .map(str::to_string)
            .collect()
    };
    assert_eq!(hub_ids(&ent(&m)), ["rule-web", "default-1"]);
    m.get_mut("profiles").unwrap()[1]["modules"][1]["data"]["segments"][0]["rules"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"name": "new", "match": {}, "action": {}}));
    assert_eq!(hub_ids(&ent(&m)), ["rule-1", "rule-web", "default-1"]);
}

#[test]
fn the_overlay_rows_hold_the_preferred_exits_of_the_edges() {
    let e = ent(&base());
    let t = e.overlay.as_ref().unwrap();
    let rows: Vec<(String, &str, u32, &ExitKind)> = t
        .rows
        .iter()
        .map(|r| (r.prefix.to_string(), r.edge.as_str(), r.segment, &r.kind))
        .collect();
    assert_eq!(
        rows,
        [
            ("10.20.20.0/24".to_string(), "e-hub", 1, &ExitKind::Learned),
            ("10.10.10.0/24".to_string(), "e-br", 1, &ExitKind::Connected),
            ("10.30.30.0/24".to_string(), "e-br", 0, &ExitKind::Static),
            (
                "10.40.40.0/24".to_string(),
                "e-hub",
                1,
                &ExitKind::Connected
            ),
            ("2001:db8::/32".to_string(), "e-br", 1, &ExitKind::Connected),
        ]
    );
    assert_eq!(t.rows[0].next_hop, Some(ip("10.9.8.2")));
    assert_eq!(t.rows[0].cost, Some(20));
    assert_eq!(t.rows[0].protocol.as_deref(), Some("BGP"));
    assert_eq!(t.rows[2].next_hop, Some(ip("10.9.9.2")));
    assert_eq!(
        t.counts,
        Counts {
            router: 1,
            withheld: 2,
            eligible: 1,
            no_edge: 0,
            no_prefix: 0,
            other_segment: 1,
        }
    );

    let mut m = base();
    m.remove("route_table");
    assert_eq!(ent(&m).overlay, None);
}

#[test]
fn the_route_order_puts_the_longest_prefix_first_and_a_static_route_with_preferred_off_last() {
    let e = ent(&base());
    let br = e.edge("e-br").unwrap();
    let statics = &br.segments[1].statics;
    assert_eq!(statics.len(), 3);
    assert_eq!(statics[0].prefix, pfx("10.50.0.0/16"));
    assert_eq!(statics[0].class(), RouteClass::LocalStaticPreferred);
    assert_eq!(statics[1].prefix, pfx("10.60.0.0/16"));
    assert_eq!(statics[1].class(), RouteClass::LocalStatic);
    assert_eq!(statics[2].interface.as_deref(), Some("GE3:10"));
    let rows = &e.overlay.as_ref().unwrap().rows;
    let overlay = RouteClass::Dynamic {
        kind: DynamicKind::Overlay {
            preferred_cost: None,
        },
        preference: None,
    };
    assert_eq!(rows[0].class("e-br"), overlay);
    assert_eq!(rows[0].class("e-hub"), RouteClass::NotKnown);
    assert_eq!(rows[1].class("e-br"), RouteClass::LocalConnected);
    assert_eq!(rows[1].class("e-hub"), RouteClass::RemoteConnected);
    assert_eq!(rows[2].class("e-br"), RouteClass::NotKnown);
    assert_eq!(rows[2].class("e-hub"), RouteClass::RemoteStatic);
    let less = Some(Ordering::Less);
    assert_eq!(
        RouteClass::RemoteStatic.order(RouteClass::LocalStatic),
        less
    );
    assert_eq!(overlay.order(RouteClass::LocalStatic), less);
    assert_eq!(
        RouteClass::LocalStaticPreferred.order(RouteClass::RemoteConnected),
        less
    );
    assert_eq!(RouteClass::NotKnown.order(RouteClass::LocalStatic), None);
    assert_eq!(overlay.order(overlay), None);
    let mut routes = [
        (statics[1].prefix, statics[1].class()),
        (rows[0].prefix, rows[0].class("e-br")),
        (statics[0].prefix, statics[0].class()),
    ];
    routes.sort_by(|a, b| order(*a, *b).unwrap());
    let got: Vec<String> = routes.iter().map(|(p, _)| p.to_string()).collect();
    assert_eq!(got, ["10.20.20.0/24", "10.50.0.0/16", "10.60.0.0/16"]);
    assert_eq!(
        order(
            (pfx("10.0.0.0/24"), RouteClass::NotKnown),
            (pfx("10.0.0.0/16"), RouteClass::LocalConnected)
        ),
        less
    );
}

#[test]
fn a_site_route_wins_over_an_overlay_route_and_a_preferred_cost_over_a_site_external_route() {
    let dynamic = |kind, preference| RouteClass::Dynamic { kind, preference };
    let site = |p| dynamic(DynamicKind::Site, Some(p));
    let external = |p| dynamic(DynamicKind::SiteExternal, Some(p));
    let overlay = |preferred_cost, p| dynamic(DynamicKind::Overlay { preferred_cost }, Some(p));
    let less = Some(Ordering::Less);
    let greater = Some(Ordering::Greater);
    assert_eq!(site(200).order(overlay(Some(true), 10)), less);
    assert_eq!(overlay(None, 10).order(site(200)), greater);
    assert_eq!(overlay(Some(true), 200).order(external(10)), less);
    assert_eq!(external(10).order(overlay(Some(true), 200)), greater);
    assert_eq!(overlay(None, 10).order(external(200)), None);
    assert_eq!(external(200).order(overlay(None, 10)), None);
    assert_eq!(overlay(Some(false), 10).order(external(200)), less);
    assert_eq!(site(20).order(site(10)), greater);
    assert_eq!(site(10).order(dynamic(DynamicKind::Site, None)), None);
}

#[test]
fn a_bgp_session_takes_the_segment_of_its_configured_neighbour() {
    let e = ent(&base());
    let s = e.sessions.as_ref().unwrap();
    let got: Vec<_> = s
        .iter()
        .map(|x| {
            (
                x.edge.as_str(),
                x.neighbour,
                &x.segment,
                x.state.as_deref(),
                x.asn,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "e-br",
                ip("10.9.9.2"),
                &SessionSegment::Segment(1),
                Some("ESTABLISHED"),
                Some(65000_u32)
            ),
            (
                "e-br",
                ip("10.9.9.99"),
                &SessionSegment::Global,
                Some("IDLE"),
                None
            ),
        ]
    );
}

#[test]
fn a_bgp_session_whose_address_is_a_neighbour_in_2_segments_has_no_known_segment() {
    let mut m = base();
    m.get_mut("profiles").unwrap()[0]["modules"][0]["data"]["segments"][0]["bgp"]["neighbors"]
        .as_array_mut()
        .unwrap()
        .push(json!({"neighborIp": "10.9.9.2", "neighborAS": "65000"}));
    let e = ent(&m);
    let s = e.sessions.as_ref().unwrap();
    let got: Vec<_> = s.iter().map(|x| (x.neighbour, &x.segment)).collect();
    assert_eq!(
        got,
        [
            (ip("10.9.9.2"), &SessionSegment::NotKnown(vec![0, 1])),
            (ip("10.9.9.99"), &SessionSegment::Global),
        ]
    );
}

#[test]
fn with_no_listing_rows_the_edges_come_from_edges_v2() {
    let mut m = base();
    m.insert("edges".into(), json!([]));
    m.remove("edge_state");
    m.insert(
        "edges_v2".into(),
        json!([{"logicalId": "e-br", "name": "branch-1"}, {"logicalId": "e-hub", "name": "hub-1"}]),
    );
    let e = ent(&m);
    assert_eq!(e.edges.len(), 2);
    assert!(e.notes.iter().any(|n| n == "edges read from edges_v2"));
    let br = e.edge("e-br").unwrap();
    assert_eq!(br.numeric_id, None);
    assert!(br.links.is_empty());
    assert_eq!(br.firewall, Policy::NotRead("no configuration".into()));
}

#[test]
fn each_edge_gives_its_facts_under_its_twin_device() {
    let mut s = Sections::new();
    s.insert(
        "edges".into(),
        (fixture_bytes("edges"), format!("{STORE}/edges@b1")),
    );
    let all = device(
        STORE,
        "velocloud",
        1_700_000_000_000,
        Some("192.0.2.80"),
        &s,
    );
    let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["vco-orch1-ent-1/edge/e-br", "vco-orch1-ent-1/edge/e-hub"]
    );
    let f = &all[0].1;
    assert_eq!(f.vendor, "velocloud");
    assert_eq!(f.store_device, STORE);
    assert_eq!(f.platform.value(), Some("edge610"));
    assert_eq!(f.os_version.value(), Some("6.4.0"));
    assert_eq!(f.serial.value(), Some("S-e-br"));
    assert_eq!(f.management_address, Fact::Unknown(Reason::NotCollected));
    let span = f.serial.span().unwrap();
    assert_eq!(&*span.file, "vco-orch1-ent-1/edges@b1");
    assert_eq!(span.first_line, span.last_line);

    let all = device(STORE, "velocloud", 1, None, &Sections::new());
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, STORE);
    assert_eq!(all[0].1.platform, Fact::Unknown(Reason::NotCollected));
}

#[test]
fn each_stanza_is_classified_and_the_same_sections_give_the_same_result() {
    let m = base();
    let p = parsed(&m);
    let cov = coverage::classify(&p);
    let total: u32 = cov.lines.values().sum();
    let lines: u32 = p.sections.values().map(|s| s.doc.lines - 2).sum();
    assert_eq!(total, lines);
    let unhandled: Vec<&str> = cov.unhandled.keys().map(String::as_str).collect();
    assert_eq!(
        unhandled,
        [
            "edge_modules/*/WAN/data/links/*/interfaces",
            "edge_modules/*/WAN/data/links/*/vlanId",
            "edge_modules/*/WAN/data/networks",
            "edge_modules/*/controlPlane/data/routingConfiguration",
            "edges/*/configuration/enterprise/modules/deviceSettings/edgeSpecificData/segments/*/bgp/neighbors/*/md5Password",
            "edges/*/ha/data/haMode",
        ]
    );
    assert!(cov.lines[&State::Unhandled] > 0);
    assert!(cov.lines[&State::Irrelevant] > 0);
    assert_eq!(coverage::classify(&parsed(&m)), cov);
    assert_eq!(ent(&m), ent(&m));
}

#[test]
fn a_key_of_an_unhandled_stanza_goes_through_the_mask() {
    let mut m = base();
    m.get_mut("bgp_sessions").unwrap()[0]["https://u:FAKEPW@192.0.2.5/x"] = json!(1);
    let cov = coverage::classify(&parsed(&m));
    let keys: Vec<&str> = cov.unhandled.keys().map(String::as_str).collect();
    assert!(
        keys.contains(&"bgp_sessions/*/https://<secret>@192.0.2.5/x"),
        "{keys:?}"
    );
    assert!(keys.iter().all(|k| !k.contains("FAKE")), "{keys:?}");
}

#[test]
fn the_masked_lines_of_each_fixture_show_no_secret() {
    for name in SECTIONS {
        let bytes = fixture_bytes(name);
        let text = section_lines("velocloud", name, Format::Json, &bytes)
            .unwrap()
            .join("\n");
        assert!(!text.contains("FAKE"), "{name}: {text}");
        assert!(text.lines().count() > 0);
    }
}
