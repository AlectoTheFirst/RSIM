//! The BGP claims on hand-built summaries: the pairing of the join and the
//! rows of `bgp-peers-up` and `bgp-peers-agree`, against the stored answers
//! `claim-bgp-*.json` in `tests/golden/`. With `RSIM_BLESS=1`, the test
//! writes the stored answers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use rsim_cli::claims::{self, BgpFacts};
use rsim_cli::json::to_text;
use rsim_contract::claim::{ClaimOut, ClaimResult};
use rsim_contract::twin::TwinJson;
use rsim_core::SourceSpan;
use rsim_ingest::bgp::{Outcome, Scope, SectionOutcome, SessionRow};
use rsim_ingest::links::{
    AddressValue, Asn, AsnValue, BgpFar, BgpPeer, BgpPeerFact, FarSide, PeerSource, Summary, join,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn asn(v: &[u32], line: u32, file: &str) -> Asn {
    Asn {
        value: AsnValue::Known(v.to_vec()),
        spans: vec![SourceSpan::line(file, line)],
    }
}

fn section(families: &[&str]) -> SectionOutcome {
    SectionOutcome {
        outcome: Outcome::Complete,
        scope: Scope(
            families
                .iter()
                .map(|f| ("default".to_string(), (*f).to_string()))
                .collect(),
        ),
        detail: None,
    }
}

/// A configured neighbour in the default VRF with IPv4 unicast, the AS that
/// the device presents, the AS of the peer and the source address.
fn neighbour(
    device: &str,
    line: u32,
    peer: &str,
    local: u32,
    remote: u32,
    src: &str,
) -> BgpPeerFact {
    let file = format!("{device}/config");
    BgpPeerFact {
        device: device.to_string(),
        vrf: "default".to_string(),
        peer: BgpPeer::Address(ip(peer)),
        source: PeerSource::Configured,
        update_source: None,
        local_address: None,
        source_address: AddressValue::Known(ip(src)),
        source_spans: vec![SourceSpan::line(format!("{device}/routes"), line)],
        local_asn: asn(&[local], 1, &file),
        peer_asn: asn(&[remote], line + 1, &file),
        observed_asn: None,
        shutdown: Some(false),
        families: BTreeSet::from(["ipv4-unicast".to_string()]),
        families_open: None,
        policy_in: None,
        policy_out: None,
        inherits: Vec::new(),
        gaps: Vec::new(),
        sessions: Vec::new(),
        router_id: None,
        section: section(&["ipv4-unicast"]),
        spans: vec![SourceSpan::new(file.as_str(), line, line + 1)],
        far: None,
    }
}

/// The fact with an update-source loopback that gives the source address.
fn loopback(mut f: BgpPeerFact, name: &str) -> BgpPeerFact {
    f.update_source = Some(name.to_string());
    f.local_address = match &f.source_address {
        AddressValue::Known(a) => Some(*a),
        AddressValue::Unknown(_) => None,
    };
    f.source_spans = Vec::new();
    f
}

/// The fact with a session row of each state word, with the prefix counts.
fn session(
    mut f: BgpPeerFact,
    state: &str,
    received: Option<u64>,
    sent: Option<u64>,
) -> BgpPeerFact {
    let BgpPeer::Address(peer) = f.peer else {
        panic!("a peer address");
    };
    let line = u32::try_from(f.sessions.len()).unwrap() + f.spans[0].first_line;
    f.sessions.push(SessionRow {
        vrf: f.vrf.clone(),
        peer,
        family: Some("ipv4-unicast".to_string()),
        peer_asn: None,
        state: state.to_string(),
        established: state == "Established",
        prefixes_received: received,
        prefixes_sent: sent,
        span: SourceSpan::line(format!("{}/bgp_sessions", f.device), line),
    });
    f
}

fn device(addresses: &[&str], peers: Vec<BgpPeerFact>) -> Summary {
    Summary {
        local_addresses: BTreeMap::from([(
            "default".to_string(),
            addresses.iter().map(|a| ip(a)).collect(),
        )]),
        bgp_peers: peers,
        bgp_read: true,
        ..Summary::default()
    }
}

/// The estate: each case of the claims on its own devices.
fn estate() -> BTreeMap<String, Summary> {
    let up = |f| session(f, "Established", Some(3), None);
    let mut d = BTreeMap::new();

    // An AS mismatch: r1 expects 64499 of r2, which presents 64497. The
    // session of r1 is Idle. A peer outside the twin and a neighbour with
    // shutdown give no row.
    let mut shut = neighbour("r1", 40, "198.51.100.30", 64496, 64505, "198.51.100.29");
    shut.shutdown = Some(true);
    let mut v6 = neighbour("r1", 50, "2001:db8::2", 64496, 64497, "2001:db8::1");
    v6.families = BTreeSet::from(["ipv6-unicast".to_string()]);
    d.insert(
        "r1".to_string(),
        device(
            &["198.51.100.1", "198.51.100.29", "2001:db8::1"],
            vec![
                session(
                    neighbour("r1", 10, "198.51.100.2", 64496, 64499, "198.51.100.1"),
                    "Idle",
                    None,
                    None,
                ),
                up(neighbour(
                    "r1",
                    20,
                    "203.0.113.200",
                    64496,
                    64510,
                    "198.51.100.1",
                )),
                shut,
                v6,
            ],
        ),
    );
    let mut v6 = neighbour("r2", 50, "2001:db8::1", 64497, 64496, "2001:db8::2");
    v6.families = BTreeSet::from(["ipv6-unicast".to_string()]);
    d.insert(
        "r2".to_string(),
        device(
            &["198.51.100.2", "2001:db8::2"],
            vec![
                up(neighbour(
                    "r2",
                    10,
                    "198.51.100.1",
                    64497,
                    64496,
                    "198.51.100.2",
                )),
                v6,
            ],
        ),
    );

    // A one-sided peering: r4 has no neighbour for r3.
    d.insert(
        "r3".to_string(),
        device(
            &["203.0.113.1"],
            vec![neighbour(
                "r3",
                10,
                "203.0.113.2",
                64498,
                64499,
                "203.0.113.1",
            )],
        ),
    );
    d.insert("r4".to_string(), device(&["203.0.113.2"], Vec::new()));

    // A source address mismatch: r5 sends from 203.0.113.6 and r3 names
    // 203.0.113.7, another address of r5; r3 sends from 203.0.113.5 and r5
    // names 203.0.113.1.
    d.insert(
        "r5".to_string(),
        device(
            &["203.0.113.6", "203.0.113.7"],
            vec![neighbour(
                "r5",
                10,
                "203.0.113.1",
                64500,
                64498,
                "203.0.113.6",
            )],
        ),
    );
    d.get_mut("r3").unwrap().bgp_peers.push(neighbour(
        "r3",
        20,
        "203.0.113.7",
        64498,
        64500,
        "203.0.113.5",
    ));
    d.get_mut("r3")
        .unwrap()
        .local_addresses
        .get_mut("default")
        .unwrap()
        .insert(ip("203.0.113.5"));

    // A local-as peering: r6 runs the AS 64501 and presents 64502 to r7.
    let mut r6 = neighbour("r6", 10, "198.51.100.14", 64502, 64503, "198.51.100.13");
    r6.local_asn = Asn {
        value: AsnValue::Known(vec![64502]),
        spans: vec![SourceSpan::line("r6/config", 12)],
    };
    d.insert("r6".to_string(), device(&["198.51.100.13"], vec![up(r6)]));
    d.insert(
        "r7".to_string(),
        device(
            &["198.51.100.14"],
            vec![up(neighbour(
                "r7",
                10,
                "198.51.100.13",
                64503,
                64502,
                "198.51.100.14",
            ))],
        ),
    );

    // A listen range: r8 accepts the peers of 198.51.100.16/29 with the AS
    // 64504, and r9 peers with r8 from 198.51.100.18.
    let mut range = neighbour("r8", 10, "198.51.100.17", 64505, 64504, "198.51.100.17");
    range.peer = BgpPeer::Range("198.51.100.16/29".parse().unwrap());
    range.source = PeerSource::ListenRange;
    range.source_address = AddressValue::Unknown("a listen range".to_string());
    d.insert("r8".to_string(), device(&["198.51.100.17"], vec![range]));
    d.insert(
        "r9".to_string(),
        device(
            &["198.51.100.18"],
            vec![up(neighbour(
                "r9",
                10,
                "198.51.100.17",
                64504,
                64505,
                "198.51.100.18",
            ))],
        ),
    );

    // iBGP over loopbacks.
    d.insert(
        "r10".to_string(),
        device(
            &["192.0.2.10", "198.51.100.33"],
            vec![up(loopback(
                neighbour("r10", 10, "192.0.2.11", 64506, 64506, "192.0.2.10"),
                "Loopback0",
            ))],
        ),
    );
    d.insert(
        "r11".to_string(),
        device(
            &["192.0.2.11", "198.51.100.34"],
            vec![up(loopback(
                neighbour("r11", 10, "192.0.2.10", 64506, 64506, "192.0.2.11"),
                "Loopback0",
            ))],
        ),
    );

    // Prefix counts that differ: r12 sent 7, r13 received 5.
    let mut r13 = neighbour("r13", 10, "198.51.100.41", 64508, 64507, "198.51.100.42");
    r13 = session(r13, "Established", Some(5), Some(5));
    d.insert(
        "r12".to_string(),
        device(
            &["198.51.100.41"],
            vec![session(
                neighbour("r12", 10, "198.51.100.42", 64507, 64508, "198.51.100.41"),
                "Established",
                Some(5),
                Some(7),
            )],
        ),
    );
    d.insert("r13".to_string(), device(&["198.51.100.42"], vec![r13]));

    // An AS that does not resolve and a source address that does not
    // resolve, with a session section that is not captured.
    let mut gap = neighbour("r14", 10, "198.51.100.50", 64509, 64509, "198.51.100.49");
    gap.peer_asn = Asn {
        value: AsnValue::Unknown(
            "inheritance gap: template peer-session MISSING not defined".to_string(),
        ),
        spans: Vec::new(),
    };
    gap.gaps = vec!["inheritance gap: template peer-session MISSING not defined".to_string()];
    gap.shutdown = None;
    let mut lost = neighbour("r14", 20, "198.51.100.54", 64509, 64511, "198.51.100.53");
    lost.source_address = AddressValue::Unknown(
        "source address not resolved: no route to 198.51.100.54 in VRF default".to_string(),
    );
    for f in [&mut gap, &mut lost] {
        f.section = SectionOutcome {
            outcome: Outcome::NotCaptured,
            scope: Scope::default(),
            detail: Some("the collector does not read the BGP sessions".to_string()),
        };
    }
    d.insert(
        "r14".to_string(),
        device(&["198.51.100.49", "198.51.100.53"], vec![gap, lost]),
    );
    d.insert(
        "r15".to_string(),
        device(
            &["198.51.100.50"],
            vec![neighbour(
                "r15",
                10,
                "198.51.100.49",
                64509,
                64509,
                "198.51.100.50",
            )],
        ),
    );
    d.insert(
        "r16".to_string(),
        device(
            &["198.51.100.54"],
            vec![neighbour(
                "r16",
                10,
                "198.51.100.53",
                64511,
                64509,
                "198.51.100.54",
            )],
        ),
    );
    d
}

fn facts() -> BgpFacts {
    join(&estate(), &BTreeSet::new(), &BTreeSet::new()).bgp
}

fn run(name: &str, scope: Option<&[&str]>) -> ClaimOut {
    let bgp = facts();
    let keep = |d: &str| scope.is_none_or(|s| s.contains(&d));
    let (evidence, detail) = match name {
        "bgp-peers-up" => claims::bgp_peers_up(&bgp, &keep),
        _ => claims::bgp_peers_agree(&bgp, &keep),
    };
    claims::out(
        "bgp-summaries",
        TwinJson::snapshot(1_795_356_312_000),
        name,
        if scope.is_some() { "devices" } else { "twin" },
        evidence,
        detail,
    )
}

#[allow(clippy::disallowed_methods)]
fn write(path: &PathBuf, text: &str) {
    std::fs::write(path, text).unwrap();
}

/// Compares the answer with its stored answer.
fn stored(file: &str, o: &ClaimOut) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(file);
    let text = to_text(o, false) + "\n";
    if std::env::var_os("RSIM_BLESS").is_some() {
        write(&path, &text);
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(text, want, "{file} differs from the stored answer");
}

fn row<'a>(o: &'a ClaimOut, subject: &str) -> &'a rsim_contract::claim::Evidence {
    o.evidence
        .iter()
        .find(|e| e.subject == subject)
        .unwrap_or_else(|| panic!("no row {subject} in {:?}", o.evidence))
}

#[test]
fn the_join_pairs_the_2_sides_on_the_transport_addresses() {
    let bgp = facts();
    let far = |d: &str, peer: &str| {
        bgp[d]
            .iter()
            .find(|f| f.peer.to_string() == peer)
            .unwrap()
            .far
            .clone()
    };
    let paired = |device: &str, i| {
        Some(BgpFar::Device {
            device: device.to_string(),
            vrf: "default".to_string(),
            side: FarSide::Paired(i),
        })
    };
    assert_eq!(far("r10", "192.0.2.11"), paired("r11", 0));
    assert_eq!(far("r9", "198.51.100.17"), paired("r8", 0));
    assert_eq!(far("r1", "203.0.113.200"), Some(BgpFar::Outside));
    assert_eq!(
        far("r3", "203.0.113.2"),
        Some(BgpFar::Device {
            device: "r4".to_string(),
            vrf: "default".to_string(),
            side: FarSide::Absent { read: true },
        })
    );
    assert!(matches!(
        far("r5", "203.0.113.1"),
        Some(BgpFar::Device {
            side: FarSide::OtherAddress(_),
            ..
        })
    ));
    // A listen range is not a neighbour with a far end.
    assert_eq!(bgp["r8"][0].far, None);
}

#[test]
fn bgp_peers_agree_refutes_a_mismatch_and_confirms_a_peering() {
    let o = run("bgp-peers-agree", None);
    assert_eq!(o.result, ClaimResult::Refuted);
    let r = |s: &str| {
        let e = row(&o, s);
        (e.result, e.detail.clone())
    };
    let (res, detail) = r("r1 vrf default neighbour 198.51.100.2");
    assert_eq!(res, ClaimResult::Refuted);
    assert!(detail.starts_with("asn mismatch"), "{detail}");
    let (res, detail) = r("r3 vrf default neighbour 203.0.113.2");
    assert_eq!(res, ClaimResult::Refuted);
    assert!(detail.starts_with("one-sided peering"), "{detail}");
    let (res, detail) = r("r5 vrf default neighbour 203.0.113.1");
    assert_eq!(res, ClaimResult::Refuted);
    assert!(detail.starts_with("source address mismatch"), "{detail}");
    for s in [
        "r6 vrf default neighbour 198.51.100.14",
        "r7 vrf default neighbour 198.51.100.13",
        "r9 vrf default neighbour 198.51.100.17",
        "r10 vrf default neighbour 192.0.2.11",
        "r11 vrf default neighbour 192.0.2.10",
        "r1 vrf default neighbour 2001:db8::2",
    ] {
        assert_eq!(r(s).0, ClaimResult::Confirmed, "{s}: {}", r(s).1);
    }
    let (res, detail) = r("r12 vrf default neighbour 198.51.100.42");
    assert_eq!(res, ClaimResult::Unknown);
    assert!(
        detail.starts_with("counts sampled at different times"),
        "{detail}"
    );
    let (res, detail) = r("r14 vrf default neighbour 198.51.100.50");
    assert_eq!(res, ClaimResult::Unknown);
    assert!(detail.contains("inheritance gap"), "{detail}");
    let (res, detail) = r("r14 vrf default neighbour 198.51.100.54");
    assert_eq!(res, ClaimResult::Unknown);
    assert!(
        detail.starts_with("source address not resolved"),
        "{detail}"
    );
    // The peer outside the twin and the neighbour with shutdown give no
    // row; the detail counts them.
    assert!(
        o.evidence
            .iter()
            .all(|e| !e.subject.contains("203.0.113.200") && !e.subject.contains("198.51.100.30"))
    );
    assert_eq!(
        o.detail,
        "left out: 1 with shutdown, 1 with the peer outside the twin"
    );
    stored("claim-bgp-peers-agree.json", &o);

    let o = run(
        "bgp-peers-agree",
        Some(&["r6", "r7", "r8", "r9", "r10", "r11"]),
    );
    assert_eq!(o.result, ClaimResult::Confirmed, "{:?}", o.evidence);
    stored("claim-bgp-peers-agree-confirmed.json", &o);
}

#[test]
fn bgp_peers_up_refutes_idle_and_is_unknown_outside_the_scope_of_the_read() {
    let o = run("bgp-peers-up", None);
    assert_eq!(o.result, ClaimResult::Refuted);
    let r = |s: &str| {
        let e = row(&o, s);
        (e.result, e.detail.clone())
    };
    assert_eq!(
        r("r1 vrf default neighbour 198.51.100.2"),
        (ClaimResult::Refuted, "state Idle".to_string())
    );
    assert_eq!(
        r("r3 vrf default neighbour 203.0.113.2"),
        (ClaimResult::Refuted, "not in session table".to_string())
    );
    assert_eq!(
        r("r10 vrf default neighbour 192.0.2.11").0,
        ClaimResult::Confirmed
    );
    // An IPv6 neighbour with no row and a section that reads IPv4 unicast
    // only.
    let (res, detail) = r("r1 vrf default neighbour 2001:db8::2");
    assert_eq!(res, ClaimResult::Unknown);
    assert!(
        detail.starts_with("address family not collected"),
        "{detail}"
    );
    let (res, detail) = r("r14 vrf default neighbour 198.51.100.54");
    assert_eq!(res, ClaimResult::Unknown);
    assert!(detail.starts_with("not collected"), "{detail}");
    // A peer outside the twin gives a row from its session state; the
    // neighbour with shutdown gives no row.
    assert_eq!(
        r("r1 vrf default neighbour 203.0.113.200").0,
        ClaimResult::Confirmed
    );
    assert!(
        o.evidence
            .iter()
            .all(|e| !e.subject.contains("198.51.100.30"))
    );
    assert_eq!(o.detail, "left out: 1 with shutdown");
    stored("claim-bgp-peers-up.json", &o);

    // A scope with no BGP neighbour is unknown.
    let o = run("bgp-peers-up", Some(&["r4"]));
    assert_eq!(o.result, ClaimResult::Unknown);
    assert!(o.evidence.is_empty());
    assert_eq!(o.detail, "no BGP neighbour in scope");
    stored("claim-bgp-peers-up-no-neighbour.json", &o);
}

#[test]
fn a_far_side_that_is_not_known_is_unknown_and_never_refuted() {
    let mut d = BTreeMap::new();
    // a1 peers with b1, whose BGP config is not read in full.
    d.insert(
        "a1".to_string(),
        device(
            &["198.51.100.1"],
            vec![neighbour(
                "a1",
                10,
                "198.51.100.2",
                64496,
                64497,
                "198.51.100.1",
            )],
        ),
    );
    let mut b1 = device(&["198.51.100.2"], Vec::new());
    b1.bgp_read = false;
    d.insert("b1".to_string(), b1);
    // a2 peers with b2, which has a session with a2 and no neighbour.
    d.insert(
        "a2".to_string(),
        device(
            &["198.51.100.5"],
            vec![neighbour(
                "a2",
                10,
                "198.51.100.6",
                64496,
                64497,
                "198.51.100.5",
            )],
        ),
    );
    let mut observed = neighbour("b2", 10, "198.51.100.5", 64497, 64496, "198.51.100.6");
    observed.source = PeerSource::Observed;
    d.insert("b2".to_string(), device(&["198.51.100.6"], vec![observed]));
    // a3 peers with an address that 2 devices have.
    d.insert(
        "a3".to_string(),
        device(
            &["198.51.100.9"],
            vec![neighbour(
                "a3",
                10,
                "198.51.100.10",
                64496,
                64497,
                "198.51.100.9",
            )],
        ),
    );
    d.insert("b3".to_string(), device(&["198.51.100.10"], Vec::new()));
    d.insert("c3".to_string(), device(&["198.51.100.10"], Vec::new()));
    // a4 peers with b4, which has 2 listen ranges that hold the source.
    d.insert(
        "a4".to_string(),
        device(
            &["198.51.100.17"],
            vec![neighbour(
                "a4",
                10,
                "198.51.100.18",
                64496,
                64497,
                "198.51.100.17",
            )],
        ),
    );
    let range = |p: &str, line| {
        let mut r = neighbour("b4", line, "198.51.100.18", 64497, 64496, "198.51.100.18");
        r.peer = BgpPeer::Range(p.parse().unwrap());
        r.source = PeerSource::ListenRange;
        r
    };
    d.insert(
        "b4".to_string(),
        device(
            &["198.51.100.18"],
            vec![range("198.51.100.16/28", 10), range("198.51.100.16/29", 20)],
        ),
    );
    let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
    let (rows, _) = claims::bgp_peers_agree(&bgp, &|_| true);
    assert_eq!(rows.len(), 4, "{rows:?}");
    for r in &rows {
        assert_eq!(r.result, ClaimResult::Unknown, "{r:?}");
    }
}

#[test]
fn the_far_neighbour_must_send_from_the_peer_address_of_the_near_side() {
    let mut d = BTreeMap::new();
    // a1 peers with 198.51.100.2 from 198.51.100.1; b1 names 198.51.100.1
    // and sends from its loopback 192.0.2.2.
    d.insert(
        "a1".to_string(),
        device(
            &["198.51.100.1"],
            vec![neighbour(
                "a1",
                10,
                "198.51.100.2",
                64496,
                64497,
                "198.51.100.1",
            )],
        ),
    );
    d.insert(
        "b1".to_string(),
        device(
            &["198.51.100.2", "192.0.2.2"],
            vec![loopback(
                neighbour("b1", 10, "198.51.100.1", 64497, 64496, "192.0.2.2"),
                "Loopback0",
            )],
        ),
    );
    // a2 peers with b2, whose source address toward a2 is not known.
    let mut lost = neighbour("b2", 10, "198.51.100.5", 64497, 64496, "198.51.100.6");
    lost.source_address =
        AddressValue::Unknown("source address not resolved: no route".to_string());
    d.insert(
        "a2".to_string(),
        device(
            &["198.51.100.5"],
            vec![neighbour(
                "a2",
                10,
                "198.51.100.6",
                64496,
                64497,
                "198.51.100.5",
            )],
        ),
    );
    d.insert("b2".to_string(), device(&["198.51.100.6"], vec![lost]));
    // a3 peers with b3, which has a dynamic peer of a listen range for the
    // source of a3 with an update-source of the range: the range satisfies
    // the second condition.
    let mut dynamic = neighbour("b3", 10, "198.51.100.9", 64497, 64496, "192.0.2.3");
    dynamic.source = PeerSource::Dynamic("198.51.100.8/29".parse().unwrap());
    d.insert(
        "a3".to_string(),
        device(
            &["198.51.100.9"],
            vec![neighbour(
                "a3",
                10,
                "198.51.100.10",
                64496,
                64497,
                "198.51.100.9",
            )],
        ),
    );
    d.insert(
        "b3".to_string(),
        device(&["198.51.100.10", "192.0.2.3"], vec![dynamic]),
    );
    let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
    let only = |dev: &str| {
        let (rows, _) = claims::bgp_peers_agree(&bgp, &|d| d == dev);
        assert_eq!(rows.len(), 1, "{rows:?}");
        rows.into_iter().next().unwrap()
    };
    let a1 = only("a1");
    assert_eq!(a1.result, ClaimResult::Refuted, "{a1:?}");
    assert!(a1.detail.starts_with("source address mismatch"), "{a1:?}");
    let a2 = only("a2");
    assert_eq!(a2.result, ClaimResult::Unknown, "{a2:?}");
    assert!(a2.detail.contains("no route"), "{a2:?}");
    let a3 = only("a3");
    assert_eq!(a3.result, ClaimResult::Confirmed, "{a3:?}");
}

#[test]
fn a_gap_that_can_hide_a_shutdown_line_turns_a_refute_into_unknown() {
    let row = |gap: bool| {
        let mut d = BTreeMap::new();
        // a expects the AS 64499 of b, which presents 64497.
        let mut a = loopback(
            neighbour("a", 10, "198.51.100.2", 64496, 64499, "198.51.100.1"),
            "Loopback0",
        );
        if gap {
            a.gaps = vec!["inheritance gap: template peer-session MISSING not defined".into()];
            a.shutdown = None;
        }
        d.insert("a".to_string(), device(&["198.51.100.1"], vec![a]));
        d.insert(
            "b".to_string(),
            device(
                &["198.51.100.2"],
                vec![neighbour(
                    "b",
                    10,
                    "198.51.100.1",
                    64497,
                    64496,
                    "198.51.100.2",
                )],
            ),
        );
        let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
        let (rows, _) = claims::bgp_peers_agree(&bgp, &|d| d == "a");
        rows.into_iter().next().unwrap()
    };
    let r = row(false);
    assert_eq!(r.result, ClaimResult::Refuted, "{r:?}");
    let r = row(true);
    assert_eq!(r.result, ClaimResult::Unknown, "{r:?}");
    assert!(r.detail.starts_with("asn mismatch"), "{r:?}");
    assert!(r.detail.contains("can hide a shutdown line"), "{r:?}");
}

#[test]
fn a_far_neighbour_of_another_session_is_no_source_address_mismatch() {
    // a has 2 sessions with b: 198.51.100.1 to 198.51.100.2 and
    // 198.51.100.5 to 198.51.100.6. b names only 198.51.100.1.
    let row = |read: bool, observed: bool| {
        let mut d = BTreeMap::new();
        d.insert(
            "a".to_string(),
            device(
                &["198.51.100.1", "198.51.100.5"],
                vec![
                    neighbour("a", 10, "198.51.100.2", 64496, 64497, "198.51.100.1"),
                    neighbour("a", 20, "198.51.100.6", 64496, 64497, "198.51.100.5"),
                ],
            ),
        );
        let mut peers = vec![neighbour(
            "b",
            10,
            "198.51.100.1",
            64497,
            64496,
            "198.51.100.2",
        )];
        if observed {
            let mut o = neighbour("b", 20, "198.51.100.5", 64497, 64496, "198.51.100.6");
            o.source = PeerSource::Observed;
            peers.push(o);
        }
        let mut b = device(&["198.51.100.2", "198.51.100.6"], peers);
        b.bgp_read = read;
        d.insert("b".to_string(), b);
        let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
        let (rows, _) = claims::bgp_peers_agree(&bgp, &|d| d == "a");
        let first = rows
            .iter()
            .find(|r| r.subject == "a vrf default neighbour 198.51.100.2")
            .unwrap();
        assert_eq!(first.result, ClaimResult::Confirmed, "{first:?}");
        rows.into_iter()
            .find(|r| r.subject == "a vrf default neighbour 198.51.100.6")
            .unwrap()
    };
    // The config of b is not read in full.
    let r = row(false, false);
    assert_eq!(r.result, ClaimResult::Unknown, "{r:?}");
    // b has a session with 198.51.100.5.
    let r = row(true, true);
    assert_eq!(r.result, ClaimResult::Unknown, "{r:?}");
    // b is read in full: its only neighbour is the far side of the other
    // session, so the peering is one-sided.
    let r = row(true, false);
    assert_eq!(r.result, ClaimResult::Refuted, "{r:?}");
    assert!(r.detail.starts_with("one-sided peering"), "{r:?}");
}

#[test]
fn disjoint_address_families_refute_only_when_both_sets_are_known_in_full() {
    let row = |gap: bool| {
        let mut d = BTreeMap::new();
        d.insert(
            "a".to_string(),
            device(
                &["198.51.100.1"],
                vec![neighbour(
                    "a",
                    10,
                    "198.51.100.2",
                    64496,
                    64497,
                    "198.51.100.1",
                )],
            ),
        );
        let mut b = neighbour("b", 10, "198.51.100.1", 64497, 64496, "198.51.100.2");
        b.families = BTreeSet::from(["ipv4-vpn".to_string()]);
        if gap {
            b.gaps = vec!["inheritance gap: template peer-policy MISSING not defined".into()];
        }
        d.insert("b".to_string(), device(&["198.51.100.2"], vec![b]));
        let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
        let (rows, _) = claims::bgp_peers_agree(&bgp, &|d| d == "a");
        rows.into_iter().next().unwrap()
    };
    let r = row(false);
    assert_eq!(r.result, ClaimResult::Refuted, "{r:?}");
    assert!(r.detail.starts_with("no common address family"), "{r:?}");
    // A gap of b can hide an activation of IPv4 unicast.
    let r = row(true);
    assert_eq!(r.result, ClaimResult::Unknown, "{r:?}");
    assert!(r.detail.contains("inheritance gap"), "{r:?}");
}

#[test]
fn bgp_peers_up_checks_a_peer_outside_the_twin_from_its_session_state() {
    let mut d = BTreeMap::new();
    // r1 peers with 2 routers of an ISP that the twin does not collect.
    let idle = session(
        neighbour("r1", 10, "203.0.113.200", 64496, 64510, "203.0.113.1"),
        "Idle",
        None,
        None,
    );
    let missing = neighbour("r1", 20, "203.0.113.201", 64496, 64510, "203.0.113.1");
    d.insert(
        "r1".to_string(),
        device(&["203.0.113.1"], vec![idle, missing]),
    );
    let bgp = join(&d, &BTreeSet::new(), &BTreeSet::new()).bgp;
    let (rows, detail) = claims::bgp_peers_up(&bgp, &|_| true);
    let r = |s: &str| rows.iter().find(|e| e.subject == s).unwrap();
    let idle = r("r1 vrf default neighbour 203.0.113.200");
    assert_eq!(
        (idle.result, idle.detail.as_str()),
        (ClaimResult::Refuted, "state Idle")
    );
    let missing = r("r1 vrf default neighbour 203.0.113.201");
    assert_eq!(
        (missing.result, missing.detail.as_str()),
        (ClaimResult::Refuted, "not in session table")
    );
    assert_eq!(detail, "");
    let (rows, detail) = claims::bgp_peers_agree(&bgp, &|_| true);
    assert!(rows.is_empty(), "{rows:?}");
    assert_eq!(
        detail,
        "no BGP neighbour in scope; left out: 2 with the peer outside the twin"
    );
}
