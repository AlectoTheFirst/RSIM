//! The BGP neighbours of the config of each vendor: the handled neighbour
//! lines, the inheritance with its gaps, the masks of the passwords, and the
//! peer facts of the estate joined with the session rows.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rsim_ingest::bgp::{self, Outcome, SessionSections};
use rsim_ingest::collected::Collected;
use rsim_ingest::coverage::Coverage;
use rsim_ingest::estate::{Estate, Input, assemble_with};
use rsim_ingest::links::{AddressValue, AsnValue, BgpFar, BgpPeerFact, FarSide, PeerSource};
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{classify, iosxe, iosxr, nxos, read_json, vyos};

fn fixture(path: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn collect_fixture(path: &str) -> Vec<u8> {
    let p = format!(
        "{}/../rsim-collect/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

const VYOS: &str = "vyos/r1-config.json";
const NXOS: &str = "nxos/leaf1-running-config.txt";
const IOSXR: &str = "iosxr/running-config.txt";
const IOSXE: &str = "iosxe/running-config.txt";

/// The route tables of a test: rows in each VRF, in no VRF, or only in the
/// default VRF.
#[derive(Clone, Copy, Debug)]
enum Rows {
    All,
    None,
    DefaultOnly,
}

impl Rows {
    fn tables(self, dynamic: BTreeMap<String, Vec<(u32, u32)>>) -> RouteTables {
        match self {
            Rows::All => RouteTables::uniform(true, dynamic),
            Rows::None => RouteTables::uniform(false, dynamic),
            Rows::DefaultOnly => RouteTables::new(["default".to_string()], dynamic),
        }
    }
}

/// The coverage and the unread handled stanzas of a config of a vendor.
fn coverage(vendor: &str, config: &[u8], rows: Rows) -> (Coverage, Vec<String>) {
    match vendor {
        "vyos" => {
            let doc = read_json(config).unwrap();
            let table = vyos::table(&rows.tables(vyos::dynamic_vrfs(&doc)));
            let cfg = vyos::read(&doc);
            (
                classify(&doc, &table),
                vyos::unread(&doc, &table, &cfg.read),
            )
        }
        "nxos" => {
            let doc = nxos::read_text(config);
            let table = nxos::table(&rows.tables(nxos::dynamic_vrfs(&doc)));
            let cfg = nxos::read(&doc, &table);
            (
                classify(&doc, &table),
                nxos::unread(&doc, &table, &cfg.read),
            )
        }
        "iosxr" => {
            let doc = iosxr::read_text(config);
            let table = iosxr::table(&rows.tables(iosxr::dynamic_vrfs(&doc)));
            let cfg = iosxr::read(&doc, &table);
            (
                classify(&doc, &table),
                iosxr::unread(&doc, &table, &cfg.read),
            )
        }
        "iosxe" => {
            let doc = iosxe::read_text(config);
            let table = iosxe::table(&rows.tables(iosxe::dynamic_vrfs(&doc)));
            let cfg = iosxe::read(&doc, &table);
            (
                classify(&doc, &table),
                iosxe::unread(&doc, &table, &cfg.read),
            )
        }
        other => panic!("no vendor {other}"),
    }
}

const FIXTURES: &[(&str, &str)] = &[
    ("vyos", VYOS),
    ("nxos", NXOS),
    ("iosxr", IOSXR),
    ("iosxe", IOSXE),
];

/// The words of the handled neighbour lines. No unhandled path ends with a
/// segment that holds one of them.
const HANDLED_WORDS: &[&str] = &[
    "remote-as",
    "update-source",
    "local-as",
    "inherit",
    "use neighbor-group",
    "use session-group",
    "peer-group",
    "confederation",
    "listen",
    "activate",
    "shutdown",
    "system-as",
];

#[test]
fn the_neighbour_lines_are_handled_and_read_in_each_vrf_state() {
    for (vendor, path) in FIXTURES {
        let config = fixture(path);
        for rows in [Rows::All, Rows::None, Rows::DefaultOnly] {
            let (cov, unread) = coverage(vendor, &config, rows);
            assert_eq!(unread, Vec::<String>::new(), "{vendor} {rows:?}");
            for p in cov.unhandled.keys() {
                let last = p.rsplit('/').next().unwrap_or_default();
                for w in HANDLED_WORDS {
                    assert!(!last.contains(w), "{vendor} {rows:?}: {p} is unhandled");
                }
            }
            // The routing lines of a BGP stanza keep the state of their VRF:
            // unhandled with no route table, known-irrelevant with one.
            let bgp_lines = cov
                .unhandled
                .keys()
                .filter(|p| p.starts_with("router bgp") || p.contains("protocols/bgp"))
                .count();
            // No unhandled stanza can hold a neighbour, so the BGP config of
            // each fixture is read in full.
            let hidden: Vec<&String> = cov
                .unhandled
                .keys()
                .filter(|p| rsim_ingest::estate::hides_peers(p))
                .collect();
            assert!(hidden.is_empty(), "{vendor} {rows:?}: {hidden:?}");
            match rows {
                Rows::All => assert_eq!(bgp_lines, 0, "{vendor}: {:?}", cov.unhandled),
                Rows::None => assert!(bgp_lines > 0, "{vendor}: {:?}", cov.unhandled),
                Rows::DefaultOnly => {}
            }
        }
    }
}

#[test]
fn a_vrf_without_rows_keeps_its_routing_lines_unhandled() {
    let (cov, _) = coverage("iosxe", &fixture(IOSXE), Rows::DefaultOnly);
    let paths: Vec<&str> = cov.unhandled.keys().map(String::as_str).collect();
    assert!(
        paths.contains(&"router bgp */address-family ipv4 vrf * ../redistribute connected"),
        "{paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|p| p.starts_with("router bgp */address-family ../")),
        "{paths:?}"
    );
    let (cov, _) = coverage("nxos", &fixture(NXOS), Rows::DefaultOnly);
    assert!(
        cov.unhandled.is_empty()
            || cov
                .unhandled
                .keys()
                .all(|p| !p.starts_with("router bgp */neighbor")),
        "{:?}",
        cov.unhandled
    );
}

fn input(vendor: &str, name: &str, config: Vec<u8>) -> Input {
    let file = format!("{name}/config@000000000000");
    let (collected, sections) = (Collected::default(), BTreeMap::new());
    match vendor {
        "vyos" => Input::Vyos {
            name: name.into(),
            config,
            file,
            collected,
        },
        "nxos" => Input::Nxos {
            name: name.into(),
            config,
            file,
            collected,
            sections,
        },
        "iosxr" => Input::Iosxr {
            name: name.into(),
            config,
            file,
            collected,
            sections,
        },
        "iosxe" => Input::Iosxe {
            name: name.into(),
            config,
            file,
            collected,
            sections,
        },
        other => panic!("no vendor {other}"),
    }
}

/// The estate of one device with its session sections.
fn estate(vendor: &str, config: Vec<u8>, sessions: SessionSections) -> Estate {
    assemble_with(
        vec![input(vendor, "d1", config)],
        &BTreeMap::from([("d1".to_string(), sessions)]),
    )
}

fn fresh(name: &str, bytes: Vec<u8>) -> (String, bgp::Collected) {
    (
        name.to_string(),
        bgp::Collected::Fresh(bytes, format!("d1/{name}@000000000000")),
    )
}

fn peer<'a>(facts: &'a [BgpPeerFact], vrf: &str, p: &str) -> &'a BgpPeerFact {
    facts
        .iter()
        .find(|f| f.vrf == vrf && f.peer.to_string() == p)
        .unwrap_or_else(|| panic!("no peer {vrf} {p} in {facts:#?}"))
}

fn known(v: &[u32]) -> AsnValue {
    AsnValue::Known(v.to_vec())
}

fn unknown_starts(a: &AsnValue, start: &str) -> bool {
    matches!(a, AsnValue::Unknown(r) if r.starts_with(start))
}

fn families(f: &BgpPeerFact) -> Vec<&str> {
    f.families.iter().map(String::as_str).collect()
}

fn addr(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn nxos_templates_local_as_confederation_and_a_listen_range() {
    let e = estate("nxos", fixture(NXOS), SessionSections::new());
    let f = &e.bgp["d1"];
    let up = peer(f, "default", "198.51.100.2");
    assert_eq!(up.source, PeerSource::Configured);
    assert_eq!(up.peer_asn.value, known(&[65001]));
    // local-as with dual-as presents the local AS and, toward a peer
    // outside the confederation, the identifier.
    assert_eq!(up.local_asn.value, known(&[64511, 64496]));
    assert_eq!(families(up), ["ipv4-unicast"]);
    assert_eq!(up.policy_in.as_deref(), Some("FROM-UPSTREAM"));
    assert_eq!(up.inherits, ["template peer-policy UPSTREAM-POLICY"]);
    assert_eq!(up.shutdown, Some(false));
    assert!(up.peer_asn.spans[0].file.starts_with("d1/config@"));

    let spine = peer(f, "default", "192.0.2.250");
    assert_eq!(spine.peer_asn.value, known(&[65000]));
    assert_eq!(spine.local_asn.value, known(&[65000]));
    assert_eq!(spine.shutdown, Some(true));
    assert_eq!(families(spine), ["l2vpn-evpn"]);
    assert_eq!(spine.update_source.as_deref(), Some("loopback0"));
    assert_eq!(spine.local_address, Some(addr("203.0.113.1")));
    assert_eq!(
        spine.inherits,
        ["template peer SPINES", "template peer-session SESSION-BASE"]
    );
    // The span of the remote AS is the line of the template.
    let line = |text: &str| {
        let c = String::from_utf8(fixture(NXOS)).unwrap();
        c.lines().position(|l| l.trim() == text).unwrap() as u32 + 1
    };
    let remote = line("template peer SPINES") + 1;
    assert_eq!(spine.peer_asn.spans[0].first_line, remote);

    let range = peer(f, "default", "198.51.100.64/28");
    assert_eq!(range.source, PeerSource::ListenRange);
    assert!(unknown_starts(
        &range.peer_asn.value,
        "asn not resolved: remote-as route-map DYNAMIC-AS"
    ));
    assert!(unknown_starts(&range.local_asn.value, "asn not resolved"));

    let red = peer(f, "RED", "203.0.113.2");
    assert_eq!(red.peer_asn.value, known(&[65551]));
    assert_eq!(red.local_asn.value, known(&[64496]));
    assert_eq!(red.section.outcome, Outcome::NotCaptured);
    assert!(!red.in_scope());
    // The summary of the switch holds the facts and the local addresses of
    // each VRF, loopbacks included.
    assert_eq!(f.len(), 4);
}

#[test]
fn iosxr_groups_local_as_and_the_vrf_neighbour() {
    let e = estate("iosxr", fixture(IOSXR), SessionSections::new());
    let f = &e.bgp["d1"];
    let rr = peer(f, "default", "203.0.113.10");
    assert_eq!(rr.peer_asn.value, known(&[64496]));
    assert_eq!(rr.local_asn.value, known(&[64496]));
    assert_eq!(rr.shutdown, Some(true));
    assert_eq!(rr.update_source.as_deref(), Some("Loopback0"));
    assert!(rr.local_address.is_some());
    assert_eq!(families(rr), ["ipv4-vpn"]);
    assert_eq!(
        rr.inherits,
        ["neighbor-group RR-CLIENTS", "session-group IBGP-SESSION"]
    );
    let ebgp = peer(f, "default", "198.51.100.20");
    assert_eq!(ebgp.local_asn.value, known(&[64505, 64500]));
    let red = peer(f, "RED", "192.0.2.10");
    assert_eq!(red.peer_asn.value, known(&[64511]));
    assert_eq!(red.local_asn.value, known(&[64500]));
    assert_eq!(
        (red.policy_in.as_deref(), red.policy_out.as_deref()),
        (Some("RP-RED-IN"), Some("PASS"))
    );
    assert_eq!(peer(f, "default", "203.0.113.9").families.len(), 1);
}

#[test]
fn iosxe_templates_peer_groups_default_activation_and_a_listen_range() {
    let e = estate("iosxe", fixture(IOSXE), SessionSections::new());
    let f = &e.bgp["d1"];
    let isp = peer(f, "default", "198.51.100.1");
    assert_eq!(isp.peer_asn.value, known(&[64511]));
    assert_eq!(isp.local_asn.value, known(&[64505, 64500]));
    assert_eq!(isp.policy_in.as_deref(), Some("FROM-ISP"));
    assert_eq!(families(isp), ["ipv4-unicast"]);
    let ibgp = peer(f, "default", "192.0.2.254");
    assert_eq!(ibgp.peer_asn.value, known(&[64496]));
    assert_eq!(ibgp.local_asn.value, known(&[64496]));
    assert_eq!(ibgp.shutdown, Some(true));
    assert_eq!(ibgp.update_source.as_deref(), Some("Loopback0"));
    assert!(ibgp.local_address.is_some());
    assert_eq!(families(ibgp), ["ipv4-unicast"]);
    assert_eq!(ibgp.inherits, ["template peer-session IBGP-BASE"]);
    let range = peer(f, "default", "198.51.100.128/26");
    assert_eq!(range.source, PeerSource::ListenRange);
    assert_eq!(range.peer_asn.value, known(&[64510]));
    assert_eq!(range.inherits, ["peer-group DYNAMIC"]);
    let red = peer(f, "RED", "203.0.113.2");
    assert_eq!(red.peer_asn.value, known(&[65551]));
    assert_eq!(families(red), ["ipv4-unicast"]);
    // The peer group is no peer.
    assert!(f.iter().all(|x| x.peer.to_string() != "DYNAMIC"));
    assert_eq!(f.len(), 4);
}

#[test]
fn iosxe_no_bgp_default_ipv4_unicast_needs_an_activate_line() {
    let config = String::from_utf8(fixture(IOSXE)).unwrap().replace(
        " bgp router-id 192.0.2.255\n",
        " bgp router-id 192.0.2.255\n no bgp default ipv4-unicast\n",
    );
    let e = estate("iosxe", config.into_bytes(), SessionSections::new());
    let f = &e.bgp["d1"];
    assert_eq!(
        families(peer(f, "default", "198.51.100.1")),
        ["ipv4-unicast"]
    );
    assert!(peer(f, "default", "192.0.2.254").families.is_empty());
}

#[test]
fn vyos_peer_groups_external_and_the_sessions_of_the_summary() {
    let sessions =
        SessionSections::from([fresh(bgp::SESSIONS, fixture("vyos/r1-bgp-sessions.json"))]);
    let e = estate("vyos", fixture(VYOS), sessions);
    let f = &e.bgp["d1"];
    let up = peer(f, "default", "192.0.2.2");
    assert_eq!(up.source, PeerSource::Configured);
    assert_eq!(up.peer_asn.value, known(&[64501]));
    assert_eq!(up.local_asn.value, known(&[64505]));
    assert_eq!(up.local_address, Some(addr("192.0.2.254")));
    assert_eq!(up.policy_in.as_deref(), Some("FROM-PEER"));
    assert_eq!(up.sessions.len(), 1);
    assert!(up.sessions[0].established);
    assert_eq!(up.observed_asn, Some(64501));
    assert!(up.in_scope());

    let shut = peer(f, "default", "198.51.100.2");
    assert_eq!(shut.shutdown, Some(true));
    assert!(unknown_starts(
        &shut.peer_asn.value,
        "asn not resolved: remote-as external"
    ));
    assert_eq!(shut.observed_asn, Some(64502));
    assert_eq!(shut.sessions[0].state, "Idle (Admin)");
    assert_eq!(shut.inherits, ["peer-group UPSTREAM"]);

    // A configured neighbour that the summary does not list.
    let absent = peer(f, "default", "198.51.100.6");
    assert!(absent.sessions.is_empty());
    assert_eq!(absent.local_asn.value, known(&[64500]));
    assert!(absent.in_scope());

    // An observed peer in the listen range takes the settings of its peer
    // group.
    let dynamic = peer(f, "default", "203.0.113.5");
    assert_eq!(
        dynamic.source,
        PeerSource::Dynamic("203.0.113.0/28".parse().unwrap())
    );
    assert_eq!(dynamic.observed_asn, Some(64510));
    assert_eq!(families(dynamic), ["ipv4-unicast"]);

    // The observed peers with no neighbour.
    let ibgp = peer(f, "default", "192.0.2.9");
    assert_eq!(ibgp.source, PeerSource::Observed);
    assert_eq!(ibgp.peer_asn.value, known(&[64496]));
    assert_eq!(ibgp.local_asn.value, known(&[64496]));
    let v6 = peer(f, "default", "2001:db8::2");
    assert_eq!(v6.source, PeerSource::Observed);
    assert_eq!(families(v6), ["ipv6-unicast"]);

    assert_eq!(
        peer(f, "default", "203.0.113.0/28").source,
        PeerSource::ListenRange
    );
    assert_eq!(f[0].section.outcome, Outcome::Complete);
    assert_eq!(f.len(), 7);
}

#[test]
fn nxos_joins_the_rows_of_the_vrfs_and_lists_the_observed_peers() {
    let sessions = SessionSections::from([fresh(
        bgp::SESSIONS,
        collect_fixture("nxos/bgp_sessions.json"),
    )]);
    let e = estate("nxos", fixture(NXOS), sessions);
    let f = &e.bgp["d1"];
    let idle = peer(f, "default", "198.51.100.2");
    assert_eq!(idle.source, PeerSource::Configured);
    assert_eq!(idle.sessions[0].state, "Idle");
    let red = peer(f, "RED", "203.0.113.2");
    assert!(red.sessions[0].established);
    assert!(red.in_scope());
    for p in ["192.0.2.2", "2001:db8::2"] {
        assert_eq!(peer(f, "default", p).source, PeerSource::Observed);
    }
    // The scope of NX-OS is IPv4 unicast, so a neighbour of EVPN only is
    // outside it.
    assert!(!peer(f, "default", "192.0.2.250").in_scope());
}

#[test]
fn a_failed_read_keeps_the_neighbours_with_the_outcome() {
    let sessions = SessionSections::from([(
        bgp::SESSIONS.to_string(),
        bgp::Collected::Failed("timeout".into()),
    )]);
    let e = estate("iosxe", fixture(IOSXE), sessions);
    let f = &e.bgp["d1"];
    assert!(f.iter().all(|x| x.section.outcome == Outcome::Failed));
    assert!(f.iter().all(|x| x.sessions.is_empty()));
}

/// The fact of a peer of a config that adds lines after a line.
fn edited(vendor: &str, path: &str, after: &str, add: &str, p: &str) -> BgpPeerFact {
    let config =
        String::from_utf8(fixture(path))
            .unwrap()
            .replacen(after, &format!("{after}{add}"), 1);
    let e = estate(vendor, config.into_bytes(), SessionSections::new());
    peer(&e.bgp["d1"], "default", p).clone()
}

#[test]
fn a_looping_template_gives_an_unknown_asn() {
    let nxos = edited(
        "nxos",
        NXOS,
        "router bgp 65000\n",
        "  template peer-session LOOP-A\n    inherit peer-session LOOP-B\n  template peer-session LOOP-B\n    inherit peer-session LOOP-A\n  neighbor 192.0.2.77\n    inherit peer-session LOOP-A\n",
        "192.0.2.77",
    );
    let iosxe = edited(
        "iosxe",
        IOSXE,
        "router bgp 64496\n",
        " template peer-session LOOP-A\n  inherit peer-session LOOP-B\n exit-peer-session\n template peer-session LOOP-B\n  inherit peer-session LOOP-A\n exit-peer-session\n neighbor 192.0.2.78 inherit peer-session LOOP-A\n",
        "192.0.2.78",
    );
    let iosxr = edited(
        "iosxr",
        IOSXR,
        "router bgp 64496\n",
        " session-group LOOP-A\n  use session-group LOOP-B\n !\n session-group LOOP-B\n  use session-group LOOP-A\n !\n neighbor 192.0.2.79\n  use session-group LOOP-A\n !\n",
        "192.0.2.79",
    );
    for f in [&nxos, &iosxe, &iosxr] {
        assert!(
            unknown_starts(&f.peer_asn.value, "inheritance gap"),
            "{:?}",
            f.peer_asn
        );
        assert!(unknown_starts(&f.local_asn.value, "inheritance gap"));
        assert_eq!(f.shutdown, None);
        assert!(
            f.gaps.iter().any(|g| g.contains("inherits from itself")),
            "{:?}",
            f.gaps
        );
    }
}

#[test]
fn a_missing_group_hides_the_settings_that_the_neighbour_does_not_state() {
    // An own remote-as stays known, and the local AS is not known, because
    // the missing group can state a local-as.
    let iosxe = edited(
        "iosxe",
        IOSXE,
        "router bgp 64496\n",
        " neighbor 192.0.2.80 remote-as 64499\n neighbor 192.0.2.80 inherit peer-session NOWHERE\n",
        "192.0.2.80",
    );
    assert_eq!(iosxe.peer_asn.value, known(&[64499]));
    assert!(unknown_starts(&iosxe.local_asn.value, "inheritance gap"));
    assert_eq!(
        iosxe.gaps,
        ["inheritance gap: template peer-session NOWHERE is not defined"]
    );
    let config = String::from_utf8(fixture(VYOS)).unwrap().replace(
        r#""198.51.100.2": {"peer-group": "UPSTREAM", "shutdown": {}},"#,
        r#""198.51.100.2": {"peer-group": "MISSING", "shutdown": {}},"#,
    );
    let e = estate("vyos", config.into_bytes(), SessionSections::new());
    let f = peer(&e.bgp["d1"], "default", "198.51.100.2");
    assert!(unknown_starts(&f.peer_asn.value, "inheritance gap"));
    assert_eq!(f.shutdown, Some(true));
}

#[test]
fn remote_as_auto_and_an_unreadable_local_as_are_unknown() {
    let config = String::from_utf8(fixture(VYOS))
        .unwrap()
        .replace(r#""remote-as": "64503","#, r#""remote-as": "auto","#);
    let e = estate("vyos", config.into_bytes(), SessionSections::new());
    let f = peer(&e.bgp["d1"], "default", "198.51.100.6");
    assert!(unknown_starts(
        &f.peer_asn.value,
        "asn not resolved: remote-as auto"
    ));
    // In a confederation the AS of the peer decides the presented AS.
    assert!(unknown_starts(&f.local_asn.value, "asn not resolved"));
    let xr = edited(
        "iosxr",
        IOSXR,
        "router bgp 64496\n",
        " neighbor 192.0.2.81\n  remote-as 64499\n  local-as 64498 prepend-twice\n !\n",
        "192.0.2.81",
    );
    assert!(unknown_starts(
        &xr.local_asn.value,
        "asn not resolved: the line local-as"
    ));
}

#[test]
fn an_asdot_process_and_remote_as_give_the_asplain_value() {
    let config = String::from_utf8(fixture(IOSXE))
        .unwrap()
        .replace("router bgp 64496\n", "router bgp 1.10\n")
        .replace(
            " neighbor 198.51.100.1 remote-as 64511\n",
            " neighbor 198.51.100.1 remote-as 64086.59904\n",
        )
        .replace(
            " neighbor 198.51.100.1 local-as 64505 no-prepend replace-as dual-as\n",
            "",
        )
        .replace(" bgp confederation identifier 64500\n", "");
    let e = estate("iosxe", config.into_bytes(), SessionSections::new());
    let f = peer(&e.bgp["d1"], "default", "198.51.100.1");
    assert_eq!(f.peer_asn.value, known(&[64086 * 65536 + 59904]));
    assert_eq!(f.local_asn.value, known(&[65546]));
}

/// The fake secrets of the fixtures.
const SECRETS: &[&str] = &[
    "FAKEBGPPASSWORD",
    "FAKETEMPLATEPASSWORD",
    "FAKEPEERGROUPPASSWORD",
    "FAKESESSIONGROUPPASSWORD",
    "FAKENEIGHBORGROUPPASSWORD",
    "FAKEVYOSPASSWORD",
];

#[test]
fn the_masks_hide_each_password_form_of_the_neighbours_and_their_groups() {
    for (line, want) in [
        ("password 3 FAKEBGPPASSWORD", "password <secret>"),
        ("password 7 FAKETEMPLATEPASSWORD", "password <secret>"),
        (
            "neighbor 198.51.100.2 password 3 FAKEBGPPASSWORD",
            "neighbor 198.51.100.2 password <secret>",
        ),
    ] {
        assert_eq!(nxos::mask(line), want, "{line}");
    }
    for (line, want) in [
        ("password encrypted FAKEBGPPASSWORD", "password <secret>"),
        (
            "password clear FAKENEIGHBORGROUPPASSWORD",
            "password <secret>",
        ),
        ("password FAKESESSIONGROUPPASSWORD", "password <secret>"),
    ] {
        assert_eq!(iosxr::mask(line), want, "{line}");
    }
    for (line, want) in [
        (
            "neighbor 198.51.100.1 password 7 FAKEBGPPASSWORD",
            "neighbor 198.51.100.1 password <secret>",
        ),
        (
            "neighbor DYNAMIC password 7 FAKEPEERGROUPPASSWORD",
            "neighbor DYNAMIC password <secret>",
        ),
        (
            "neighbor 198.51.100.1 password 0 FAKEBGPPASSWORD",
            "neighbor 198.51.100.1 password <secret>",
        ),
        ("password FAKETEMPLATEPASSWORD", "password <secret>"),
    ] {
        assert_eq!(iosxe::mask(line), want, "{line}");
    }
    // No report, unread list, note or peer fact of a fixture holds a fake
    // secret, with or without route tables. A VyOS report holds keys only,
    // and the password is the value of its key.
    for (vendor, path) in FIXTURES {
        let config = fixture(path);
        for rows in [Rows::All, Rows::None] {
            let (cov, unread) = coverage(vendor, &config, rows);
            let text = format!("{:?} {unread:?}", cov.unhandled);
            for s in SECRETS {
                assert!(!text.contains(s), "{vendor} {rows:?}: {s} in {text}");
            }
        }
        let e = estate(vendor, config, SessionSections::new());
        let text = format!("{:?} {:?} {:?}", e.bgp, e.notes, e.coverage);
        for s in SECRETS {
            assert!(!text.contains(s), "{vendor}: {s} in the estate");
        }
    }
}

/// The facts of a config that replaces each text with its replacement.
fn replaced(vendor: &str, path: &str, edits: &[(&str, &str)]) -> Vec<BgpPeerFact> {
    let mut config = String::from_utf8(fixture(path)).unwrap();
    for (from, to) in edits {
        assert!(config.contains(from), "{from}");
        config = config.replacen(from, to, 1);
    }
    let e = estate(vendor, config.into_bytes(), SessionSections::new());
    e.bgp["d1"].clone()
}

#[test]
fn a_gap_before_a_source_hides_the_settings_of_that_source() {
    // The missing neighbor-group comes before the session-group, so the
    // session-group gives no remote-as and no shutdown.
    let xr = edited(
        "iosxr",
        IOSXR,
        "router bgp 64496\n",
        " session-group SG\n  remote-as 64502\n  shutdown\n !\n neighbor 192.0.2.82\n  use neighbor-group NG\n  use session-group SG\n !\n",
        "192.0.2.82",
    );
    assert!(
        unknown_starts(&xr.peer_asn.value, "inheritance gap"),
        "{:?}",
        xr.peer_asn
    );
    assert_eq!(xr.shutdown, None);
    // The missing template comes before the peer group.
    let xe = edited(
        "iosxe",
        IOSXE,
        "router bgp 64496\n",
        " neighbor G2 peer-group\n neighbor G2 remote-as 64502\n neighbor 192.0.2.83 inherit peer-session NOWHERE\n neighbor 192.0.2.83 peer-group G2\n",
        "192.0.2.83",
    );
    assert!(
        unknown_starts(&xe.peer_asn.value, "inheritance gap"),
        "{:?}",
        xe.peer_asn
    );
}

#[test]
fn iosxr_shutdown_inheritance_disable_keeps_the_session_up() {
    let add = " neighbor-group NGS\n  remote-as 64496\n  shutdown\n !\n neighbor 192.0.2.84\n  use neighbor-group NGS\n  shutdown inheritance-disable\n !\n";
    let f = edited("iosxr", IOSXR, "router bgp 64496\n", add, "192.0.2.84");
    assert_eq!(f.peer_asn.value, known(&[64496]));
    assert_eq!(f.shutdown, Some(false));
    let config = String::from_utf8(fixture(IOSXR)).unwrap().replacen(
        "router bgp 64496\n",
        &format!("router bgp 64496\n{add}"),
        1,
    );
    let (cov, unread) = coverage("iosxr", config.as_bytes(), Rows::All);
    assert!(
        cov.unhandled
            .keys()
            .all(|k| !k.contains("inheritance-disable")),
        "{:?}",
        cov.unhandled
    );
    assert!(
        unread.iter().all(|k| !k.contains("inheritance-disable")),
        "{unread:?}"
    );
}

#[test]
fn iosxe_peer_groups_of_the_same_name_belong_to_their_vrf() {
    // The VRF `RED` sorts before `default` and `zed` after it.
    for vrf in ["RED", "zed"] {
        let in_vrf = format!(
            " address-family ipv4 vrf {vrf}\n  neighbor G peer-group\n  neighbor G remote-as 64502\n  neighbor G inherit peer-policy VRF-POLICY\n  neighbor 203.0.113.9 peer-group G\n"
        );
        let f = replaced(
            "iosxe",
            IOSXE,
            &[
                (
                    "router bgp 64496\n",
                    "router bgp 64496\n template peer-policy VRF-POLICY\n  route-map VRF-IN in\n exit-peer-policy\n",
                ),
                (
                    "  network 192.0.2.0 mask 255.255.255.0\n",
                    "  network 192.0.2.0 mask 255.255.255.0\n  neighbor G peer-group\n  neighbor G remote-as 64501\n  neighbor 192.0.2.85 peer-group G\n",
                ),
                (" address-family ipv4 vrf RED\n", &in_vrf),
            ],
        );
        let global = peer(&f, "default", "192.0.2.85");
        assert_eq!(global.peer_asn.value, known(&[64501]), "{vrf}");
        assert_eq!(global.policy_in, None, "{vrf}");
        let member = peer(&f, vrf, "203.0.113.9");
        assert_eq!(member.peer_asn.value, known(&[64502]), "{vrf}");
        assert_eq!(member.policy_in.as_deref(), Some("VRF-IN"), "{vrf}");
    }
}

#[test]
fn a_peer_policy_of_another_family_gives_no_ipv4_unicast_policy() {
    let nxos = edited(
        "nxos",
        NXOS,
        "router bgp 65000\n",
        "  template peer-policy EVPN\n    route-map EVPN-OUT out\n  neighbor 192.0.2.86\n    remote-as 65000\n    address-family l2vpn evpn\n      inherit peer-policy EVPN 10\n",
        "192.0.2.86",
    );
    assert_eq!(nxos.policy_out, None);
    assert_eq!(nxos.inherits, ["template peer-policy EVPN"]);
    // A peer-policy of VPNv4 and of a family that the reader does not name
    // gives no policy; one of IPv4 unicast gives its policy.
    let f = replaced(
        "iosxe",
        IOSXE,
        &[(
            "router bgp 64496\n",
            "router bgp 64496\n template peer-policy VPN\n  route-map VPN-OUT out\n exit-peer-policy\n neighbor 192.0.2.87 remote-as 64496\n neighbor 192.0.2.88 remote-as 64496\n neighbor 192.0.2.89 remote-as 64496\n address-family vpnv4\n  neighbor 192.0.2.87 activate\n  neighbor 192.0.2.87 inherit peer-policy VPN\n exit-address-family\n address-family rtfilter unicast\n  neighbor 192.0.2.88 inherit peer-policy VPN\n exit-address-family\n address-family ipv4 unicast\n  neighbor 192.0.2.89 inherit peer-policy VPN\n exit-address-family\n",
        )],
    );
    assert_eq!(peer(&f, "default", "192.0.2.87").policy_out, None);
    assert_eq!(peer(&f, "default", "192.0.2.88").policy_out, None);
    assert_eq!(
        peer(&f, "default", "192.0.2.89").policy_out.as_deref(),
        Some("VPN-OUT")
    );
}

#[test]
fn the_local_address_of_an_update_source_has_the_family_of_the_peer() {
    let f = replaced(
        "iosxr",
        IOSXR,
        &[(
            "router bgp 64496\n",
            "router bgp 64496\n neighbor 2001:db8::2\n  remote-as 64496\n  update-source Loopback0\n !\n",
        )],
    );
    assert_eq!(
        peer(&f, "default", "2001:db8::2").local_address,
        Some(addr("2001:db8::1"))
    );
    assert_eq!(
        peer(&f, "default", "203.0.113.9").local_address,
        Some(addr("203.0.113.1"))
    );
}

#[test]
fn an_iosxe_listen_range_takes_the_default_activation_of_ipv4_unicast() {
    let f = replaced(
        "iosxe",
        IOSXE,
        &[
            (" neighbor DYNAMIC activate\n", ""),
            (
                " address-family ipv4 vrf RED\n",
                " address-family ipv6\n  neighbor DYNAMIC activate\n exit-address-family\n !\n address-family ipv4 vrf RED\n",
            ),
        ],
    );
    assert_eq!(
        families(peer(&f, "default", "198.51.100.128/26")),
        ["ipv4-unicast", "ipv6-unicast"]
    );
}

#[test]
fn an_address_family_that_the_reader_does_not_name_leaves_the_families_open() {
    let nxos = edited(
        "nxos",
        NXOS,
        "router bgp 65000\n",
        "  neighbor 192.0.2.90\n    remote-as 64500\n    address-family ipv4 mvpn\n    address-family ipv4 unicast\n",
        "192.0.2.90",
    );
    assert_eq!(families(&nxos), ["ipv4-unicast"]);
    let iosxe = edited(
        "iosxe",
        IOSXE,
        " address-family ipv4 vrf RED\n",
        " address-family ipv4 mvpn\n  neighbor 198.51.100.1 activate\n exit-address-family\n !\n address-family ipv4 vrf RED\n",
        "198.51.100.1",
    );
    for f in [&nxos, &iosxe] {
        assert!(
            f.families_open
                .as_deref()
                .is_some_and(|r| r.contains("ipv4 mvpn")),
            "{:?}",
            f.families_open
        );
    }
    // A gap can hide an activation.
    let gap = edited(
        "iosxe",
        IOSXE,
        "router bgp 64496\n",
        " neighbor 192.0.2.91 remote-as 64499\n neighbor 192.0.2.91 inherit peer-session NOWHERE\n",
        "192.0.2.91",
    );
    assert!(
        gap.families_open
            .as_deref()
            .is_some_and(|r| r.starts_with("inheritance gap")),
        "{:?}",
        gap.families_open
    );
    let plain = edited(
        "iosxe",
        IOSXE,
        "router bgp 64496\n",
        " neighbor 192.0.2.92 remote-as 64499\n",
        "192.0.2.92",
    );
    assert_eq!(plain.families_open, None);
}

/// The sections of the IOS-XR fixture, with the route table.
fn iosxr_sections(device: &str) -> BTreeMap<String, (Vec<u8>, String)> {
    iosxr::SECTIONS
        .iter()
        .map(|n| {
            (
                n.to_string(),
                (fixture(&format!("iosxr/{n}.txt")), format!("{device}/{n}")),
            )
        })
        .collect()
}

#[test]
fn a_bgp_stanza_that_the_route_rows_make_irrelevant_makes_the_config_not_read() {
    // r1 peers with the loopback of xr from 203.0.113.129. With the
    // instance, xr has the neighbour only in a BGP instance that the reader
    // does not read.
    let far_side = |instance: bool| {
        let mut xr = String::from_utf8(fixture(IOSXR)).unwrap();
        if instance {
            xr = xr.replacen(
                "router bgp 64496\n",
                "router bgp 64496 instance CORE\n neighbor 203.0.113.129\n  remote-as 64496\n !\n!\nrouter bgp 64496\n",
                1,
            );
        }
        let vyos = String::from_utf8(fixture(VYOS)).unwrap().replacen(
            r#""198.51.100.6": {"#,
            r#""203.0.113.1": {"remote-as": "64496", "update-source": "203.0.113.129"},
        "198.51.100.6": {"#,
            1,
        );
        let e = assemble_with(
            vec![
                input("vyos", "r1", vyos.into_bytes()),
                Input::Iosxr {
                    name: "xr".into(),
                    config: xr.into_bytes(),
                    file: "xr/config@000000000000".into(),
                    collected: Collected::default(),
                    sections: iosxr_sections("xr"),
                },
            ],
            &BTreeMap::new(),
        );
        let f = peer(&e.bgp["r1"], "default", "203.0.113.1");
        assert_eq!(f.source_address, AddressValue::Known(addr("203.0.113.129")));
        match &f.far {
            Some(BgpFar::Device { device, side, .. }) if device == "xr" => side.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(far_side(false), FarSide::Absent { read: true });
    assert_eq!(far_side(true), FarSide::Absent { read: false });
}

#[test]
fn an_ipv6_address_of_an_nxos_switch_is_an_address_of_the_twin() {
    let nxos = String::from_utf8(fixture(NXOS)).unwrap().replacen(
        "  ip address 198.51.100.1/30\n",
        "  ip address 198.51.100.1/30\n  ipv6 address 2001:db8:5::1/64\n",
        1,
    );
    let vyos = String::from_utf8(fixture(VYOS)).unwrap().replacen(
        r#""198.51.100.6": {"#,
        r#""2001:db8:5::1": {"remote-as": "64500"},
        "198.51.100.6": {"#,
        1,
    );
    let e = assemble_with(
        vec![
            input("vyos", "r1", vyos.into_bytes()),
            input("nxos", "sw", nxos.into_bytes()),
        ],
        &BTreeMap::new(),
    );
    let f = peer(&e.bgp["r1"], "default", "2001:db8:5::1");
    assert!(
        matches!(&f.far, Some(BgpFar::Device { device, .. }) if device == "sw"),
        "{:?}",
        f.far
    );
}
