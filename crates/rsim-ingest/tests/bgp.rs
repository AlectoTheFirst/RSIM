//! The BGP session sections of the collector fixtures: the rows, the
//! outcome of each read and its scope.

use std::collections::BTreeSet;

use rsim_ingest::bgp::{
    self, Answer, IPV4_UNICAST, Outcome, Scope, SectionOutcome, SessionRow, Sessions,
};
use rsim_store::{Class, Format, SectionEntry, SectionStatus};

fn fixture(path: &str) -> String {
    let p = format!(
        "{}/../rsim-collect/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn fresh(text: &str) -> Answer<'_> {
    Answer::Fresh(text.as_bytes(), "r1/bgp_sessions")
}

fn scope(names: &[&str]) -> Scope {
    Scope(names.iter().map(|s| s.to_string()).collect())
}

fn row<'a>(s: &'a Sessions, vrf: &str, peer: &str) -> &'a SessionRow {
    s.rows
        .iter()
        .find(|r| r.vrf == vrf && r.peer.to_string() == peer)
        .unwrap_or_else(|| panic!("no row {vrf} {peer} in {:?}", s.rows))
}

fn outcome(s: &Sessions) -> Outcome {
    s.outcome.outcome
}

#[test]
fn vyos_reads_each_family_of_each_vrf_and_a_down_peer() {
    let text = fixture("vyos/bgp_sessions.json");
    let s = bgp::vyos(fresh(&text));
    assert_eq!(outcome(&s), Outcome::Complete, "{:?}", s.outcome);
    assert_eq!(s.outcome.vrfs, scope(&["RED", "default"]));
    assert_eq!(
        s.outcome.families,
        scope(&[IPV4_UNICAST, "ipv6-unicast", "l2vpn-evpn"])
    );
    assert_eq!(s.rows.len(), 5);
    let up = row(&s, "default", "192.0.2.2");
    assert!(up.established);
    assert_eq!(
        (
            up.prefixes_received,
            up.prefixes_sent,
            up.peer_asn.as_deref()
        ),
        (Some(3), Some(2), Some("64501"))
    );
    assert!(up.span.first_line > 1 && up.span.last_line > up.span.first_line);
    let down = row(&s, "default", "198.51.100.2");
    assert!(!down.established);
    assert_eq!(down.state, "Active");
    assert_eq!(
        row(&s, "default", "2001:db8::2").family.as_deref(),
        Some("ipv6-unicast")
    );
    assert_eq!(
        row(&s, "default", "192.0.2.9").family.as_deref(),
        Some("l2vpn-evpn")
    );
    assert_eq!(
        row(&s, "RED", "203.0.113.2").peer_asn.as_deref(),
        Some("65551")
    );
}

#[test]
fn vyos_outcomes_of_an_empty_a_misread_and_a_missing_answer() {
    let s = bgp::vyos(fresh("{}"));
    assert_eq!(outcome(&s), Outcome::CompleteEmpty);
    assert_eq!(s.outcome.vrfs, Scope::default());

    assert_eq!(outcome(&bgp::vyos(fresh("not json"))), Outcome::Failed);
    let unread = r#"{"default":{"ipv4Unicast":{"peers":{"192.0.2.2":{"remoteAs":64501}}}}}"#;
    let s = bgp::vyos(fresh(unread));
    assert_eq!(outcome(&s), Outcome::Failed, "{:?}", s.outcome);
    let text = fixture("vyos/bgp_sessions.json").replace("\"state\": \"Active\",", "");
    let s = bgp::vyos(fresh(&text));
    assert_eq!(outcome(&s), Outcome::Partial);
    assert!(s.outcome.detail.unwrap().contains("198.51.100.2"));
    assert_eq!(s.rows.len(), 4);

    assert_eq!(
        outcome(&bgp::vyos(Answer::NotCollected)),
        Outcome::NotCaptured
    );
    assert_eq!(
        outcome(&bgp::vyos(Answer::Absent("% BGP instance not found"))),
        Outcome::NotCaptured
    );
    let old = SectionEntry {
        name: "bgp_sessions".into(),
        command: "vtysh".into(),
        class: Class::Observation,
        format: Format::Json,
        change_hash: None,
        blob: None,
        status: SectionStatus::Old {
            error: "timeout".into(),
        },
        collected_at: None,
    };
    let s = bgp::vyos(Answer::of(Some(&old), Some(text.as_bytes()), "f"));
    assert_eq!(outcome(&s), Outcome::Failed);
    assert!(s.rows.is_empty());
}

#[test]
fn nxos_reads_the_vrf_rows_and_covers_ipv4_unicast_only() {
    let text = fixture("nxos/bgp_sessions.json");
    let s = bgp::nxos(fresh(&text), Answer::Absent("not sent"));
    assert_eq!(outcome(&s), Outcome::Complete, "{:?}", s.outcome);
    assert_eq!(s.outcome.vrfs, scope(&["RED", "default"]));
    assert_eq!(s.outcome.families, scope(&[IPV4_UNICAST]));
    assert!(!s.outcome.families.covers("ipv6-unicast"));
    assert_eq!(s.rows.len(), 4);
    assert_eq!(row(&s, "default", "198.51.100.2").state, "Idle");
    assert!(!row(&s, "default", "198.51.100.2").established);
    assert!(row(&s, "RED", "203.0.113.2").established);
    assert_eq!(row(&s, "RED", "203.0.113.2").family, None);
    assert!(row(&s, "default", "2001:db8::2").established);
}

#[test]
fn nxos_falls_back_to_the_global_table_and_guards_a_misread() {
    let text = fixture("nxos/bgp_sessions.json");
    let s = bgp::nxos(Answer::Absent("% Invalid command"), fresh(&text));
    assert_eq!(s.outcome.vrfs, scope(&["default"]));
    let s = bgp::nxos(
        Answer::Absent("% Invalid command"),
        Answer::Absent("% Invalid command"),
    );
    assert_eq!(outcome(&s), Outcome::NotCaptured);
    let s = bgp::nxos(
        Answer::Absent("% Invalid command"),
        Answer::Failed("timeout"),
    );
    assert_eq!(outcome(&s), Outcome::Failed);
    let s = bgp::nxos(Answer::Failed("timeout"), Answer::Absent("not sent"));
    assert_eq!(outcome(&s), Outcome::Failed);

    assert_eq!(
        outcome(&bgp::nxos(fresh("{}"), Answer::Absent("not sent"))),
        Outcome::CompleteEmpty
    );
    assert_eq!(
        outcome(&bgp::nxos(
            fresh(r#"{"peers": 1}"#),
            Answer::Absent("not sent")
        )),
        Outcome::Failed
    );
    let renamed = text.replace("\"state\"", "\"session-state\"");
    assert_eq!(
        outcome(&bgp::nxos(fresh(&renamed), Answer::Absent("not sent"))),
        Outcome::Failed
    );
    let one = text.replacen("\"state\": \"Idle\"", "\"st\": \"Idle\"", 1);
    let s = bgp::nxos(fresh(&one), Answer::Absent("not sent"));
    assert_eq!(outcome(&s), Outcome::Partial);
    assert_eq!(s.rows.len(), 3);
}

fn vrfs_text(red: &str) -> String {
    format!("VRF: BLUE failed\nVRF: RED\n{red}")
}

#[test]
fn iosxr_reads_the_columns_of_each_vrf_and_a_failed_vrf_is_partial() {
    let global = fixture("iosxr/bgp_sessions.txt");
    let red = fixture("iosxr/bgp_vrf_red.txt");
    let vrfs = vrfs_text(&red);
    let s = bgp::iosxr(fresh(&global), fresh(&vrfs));
    assert_eq!(outcome(&s), Outcome::Partial, "{:?}", s.outcome);
    assert_eq!(s.outcome.vrfs, scope(&["RED", "default"]));
    assert!(s.outcome.detail.as_deref().unwrap().contains("BLUE"));
    assert_eq!(s.rows.len(), 4);
    let up = row(&s, "default", "192.0.2.2");
    assert!(up.established);
    assert_eq!(
        (up.prefixes_received, up.peer_asn.as_deref()),
        (Some(3), Some("64501"))
    );
    assert_eq!((up.span.first_line, up.span.last_line), (19, 19));
    assert_eq!(row(&s, "default", "198.51.100.6").state, "Idle (Admin)");
    assert_eq!(row(&s, "default", "198.51.100.2").state, "Idle");
    let r = row(&s, "RED", "203.0.113.2");
    assert_eq!((r.span.first_line, r.prefixes_received), (22, Some(1)));

    let s = bgp::iosxr(fresh(&global), fresh(&format!("VRF: RED\n{red}")));
    assert_eq!(outcome(&s), Outcome::Complete, "{:?}", s.outcome);
    let s = bgp::iosxr(fresh(&global), fresh(""));
    assert_eq!(outcome(&s), Outcome::Complete);
    assert_eq!(s.outcome.vrfs, scope(&["default"]));
}

#[test]
fn iosxr_outcomes_of_no_bgp_a_misread_and_an_empty_table() {
    let none = "Tue Nov 17 10:00:00.000 UTC\n% BGP instance 'default' not active\n";
    let s = bgp::iosxr(fresh(none), fresh(""));
    assert_eq!(outcome(&s), Outcome::NotCaptured, "{:?}", s.outcome);

    let global = fixture("iosxr/bgp_sessions.txt");
    let garbled = global
        .replace(" 0 64501 ", " x 64501 ")
        .replace(" 0 64502 ", " x 64502 ")
        .replace(" 0 64503 ", " x 64503 ");
    let s = bgp::iosxr(fresh(&garbled), Answer::NotCollected);
    assert_eq!(outcome(&s), Outcome::Failed, "{:?}", s.outcome);
    assert!(s.outcome.vrfs.0.is_empty());

    let one = global.replace(" 0 64502 ", " x 64502 ");
    let s = bgp::iosxr(fresh(&one), Answer::NotCollected);
    assert_eq!(outcome(&s), Outcome::Partial);
    assert_eq!(s.rows.len(), 2);

    let no_header = global.replace("BGP router identifier", "BGP router-id");
    assert_eq!(
        outcome(&bgp::iosxr(fresh(&no_header), Answer::NotCollected)),
        Outcome::Failed
    );

    let empty: String = global
        .lines()
        .filter(|l| !l.starts_with("192.") && !l.starts_with("198."))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(
        outcome(&bgp::iosxr(fresh(&empty), Answer::NotCollected)),
        Outcome::CompleteEmpty
    );
    assert_eq!(
        outcome(&bgp::iosxr(Answer::NotCollected, Answer::NotCollected)),
        Outcome::NotCaptured
    );
}

#[test]
fn iosxe_reads_the_template_rows_with_a_dynamic_peer() {
    let global = fixture("iosxe/bgp_sessions.txt");
    let red = fixture("iosxe/bgp_vrf_red.txt");
    let s = bgp::iosxe(fresh(&global), fresh(&format!("VRF: RED\n{red}")));
    assert_eq!(outcome(&s), Outcome::Complete, "{:?}", s.outcome);
    assert_eq!(s.outcome.vrfs, scope(&["RED", "default"]));
    assert_eq!(s.rows.len(), 5);
    let dynamic = row(&s, "default", "203.0.113.7");
    assert!(dynamic.established);
    assert_eq!(dynamic.prefixes_received, Some(1));
    assert_eq!(dynamic.span.first_line, 17);
    assert_eq!(row(&s, "default", "192.0.2.2").span.first_line, 14);
    assert_eq!(row(&s, "default", "198.51.100.6").state, "Idle (Admin)");
    assert_eq!(row(&s, "RED", "203.0.113.2").span.first_line, 12);
    let found: BTreeSet<String> = s.rows.iter().map(|r| r.peer.to_string()).collect();
    assert!(!found.contains("203.0.113.0"));
}

#[test]
fn iosxe_outcomes_of_no_bgp_and_a_misread_row() {
    let s = bgp::iosxe(fresh("% BGP not active\n"), fresh(""));
    assert_eq!(outcome(&s), Outcome::NotCaptured);
    assert_eq!(
        s.outcome,
        SectionOutcome {
            outcome: Outcome::NotCaptured,
            vrfs: Scope::default(),
            families: scope(&[IPV4_UNICAST]),
            detail: Some("default: % BGP not active".into()),
        }
    );
    let global = fixture("iosxe/bgp_sessions.txt");
    let one = global.replace("198.51.100.2    4 ", "198.51.100.2    v4 ");
    let s = bgp::iosxe(fresh(&one), fresh(""));
    assert_eq!(outcome(&s), Outcome::Partial, "{:?}", s.outcome);
    assert_eq!(s.rows.len(), 3);
    assert!(s.outcome.detail.unwrap().contains("line 15"));
    let s = bgp::iosxe(fresh(&global), Answer::Failed("the connect failed"));
    assert_eq!(outcome(&s), Outcome::Partial);
    assert_eq!(s.outcome.vrfs, scope(&["default"]));
}
