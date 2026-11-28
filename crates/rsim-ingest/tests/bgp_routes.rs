//! The section `bgp_routes` of each vendor in `tests/fixtures/bgp/`: the 3
//! tables of each neighbour, with a wrapped network line in the text
//! tables, a prefix with 2 paths, an empty table, a table whose prefix
//! counter does not agree with its rows, and a failed command.

use rsim_core::Prefix;
use rsim_ingest::bgp::{Answer, Outcome};
use rsim_ingest::bgp_routes::{Direction, Table, read};
use rsim_routing::bgp::{AsPath, BgpOrigin, Community};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/bgp/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).unwrap()
}

fn tables(vendor: &str, name: &str) -> Vec<Table> {
    let bytes = fixture(name);
    read(vendor, Answer::Fresh(&bytes, "r1/bgp_routes"))
}

/// The VRF, the peer, the direction, the outcome and the number of rows of
/// each table.
fn shape(t: &[Table]) -> Vec<(String, String, Direction, Outcome, usize)> {
    t.iter()
        .map(|x| {
            (
                x.vrf.clone(),
                x.peer.to_string(),
                x.direction,
                x.outcome,
                x.rows.len(),
            )
        })
        .collect()
}

fn s(x: &str) -> String {
    x.to_string()
}

fn p(x: &str) -> Prefix {
    x.parse().unwrap()
}

#[test]
fn the_ios_xe_tables_with_a_wrapped_network_and_2_paths_of_a_prefix() {
    use Direction::*;
    use Outcome::*;
    let t = tables("iosxe", "routes-iosxe.txt");
    assert_eq!(
        shape(&t),
        [
            (s("default"), s("192.0.2.1"), Received, Complete, 4),
            (s("default"), s("192.0.2.1"), Accepted, Complete, 4),
            (s("default"), s("192.0.2.1"), Advertised, CompleteEmpty, 0),
            (s("RED"), s("203.0.113.9"), Received, Failed, 0),
            (s("RED"), s("203.0.113.9"), Accepted, Failed, 0),
            (s("RED"), s("203.0.113.9"), Advertised, Failed, 0),
        ]
    );
    let rows = &t[1].rows;
    assert_eq!(rows[0].prefix, p("10.0.0.0/8"));
    assert_eq!(rows[1].prefix, p("100.100.100.128/25"));
    assert_eq!(rows[1].as_path, Some(AsPath::sequence(&[64500, 64511])));
    assert_eq!(rows[1].origin, Some(BgpOrigin::Incomplete));
    assert_eq!(rows[1].span.first_line + 1, rows[1].span.last_line);
    assert_eq!(rows[2].prefix, rows[3].prefix);
    assert!(rows[2].best && !rows[3].best);
    assert_eq!(rows[3].med, Some(20));
    assert_eq!(rows[3].communities, None);
    assert!(
        t[4].detail
            .as_deref()
            .unwrap()
            .contains("states 2 prefixes and its table has 1")
    );
}

#[test]
fn the_ios_xr_tables_with_the_table_of_the_advertised_routes() {
    use Direction::*;
    use Outcome::*;
    let t = tables("iosxr", "routes-iosxr.txt");
    assert_eq!(
        shape(&t),
        [
            (s("default"), s("192.0.2.1"), Received, Complete, 4),
            (s("default"), s("192.0.2.1"), Accepted, Complete, 4),
            (s("default"), s("192.0.2.1"), Advertised, Complete, 2),
            (s("default"), s("192.0.2.5"), Received, CompleteEmpty, 0),
            (s("default"), s("192.0.2.5"), Accepted, CompleteEmpty, 0),
            (s("default"), s("192.0.2.5"), Advertised, CompleteEmpty, 0),
        ]
    );
    let rows = &t[1].rows;
    assert_eq!(rows[1].prefix, p("100.100.100.128/25"));
    assert_eq!(rows[1].local_pref, Some(100));
    assert_eq!(
        rows[3].as_path,
        Some(AsPath::sequence(&[64500, 64499, 64510]))
    );
    let adv = &t[2].rows;
    assert_eq!(adv[0].as_path, Some(AsPath::default()));
    assert_eq!(adv[1].as_path, Some(AsPath::sequence(&[64510, 64511])));
}

#[test]
fn the_nxos_tables_with_2_paths_an_empty_table_and_failed_commands() {
    use Direction::*;
    use Outcome::*;
    let t = tables("nxos", "routes-nxos.json");
    assert_eq!(
        shape(&t),
        [
            (s("RED"), s("203.0.113.9"), Received, Failed, 0),
            (s("RED"), s("203.0.113.9"), Accepted, Failed, 0),
            (s("RED"), s("203.0.113.9"), Advertised, Failed, 0),
            (s("default"), s("192.0.2.1"), Received, Complete, 3),
            (s("default"), s("192.0.2.1"), Accepted, Complete, 3),
            (s("default"), s("192.0.2.1"), Advertised, CompleteEmpty, 0),
        ]
    );
    let rows = &t[4].rows;
    assert_eq!(
        rows[0].communities,
        Some([Community::new(64500, 1), Community::new(64500, 2)].into())
    );
    assert_eq!(rows[1].prefix, rows[2].prefix);
    assert!(rows[1].best && !rows[2].best);
    assert_eq!(rows[2].origin, Some(BgpOrigin::Incomplete));
}

#[test]
fn the_vyos_tables_check_the_table_key_and_the_prefix_counter() {
    use Direction::*;
    use Outcome::*;
    let t = tables("vyos", "routes-vyos.json");
    assert_eq!(
        shape(&t),
        [
            (s("default"), s("192.0.2.1"), Received, Complete, 2),
            (s("default"), s("192.0.2.1"), Accepted, Complete, 3),
            (s("default"), s("192.0.2.1"), Advertised, CompleteEmpty, 0),
            (s("default"), s("192.0.2.5"), Received, Failed, 0),
            (s("default"), s("192.0.2.5"), Accepted, Failed, 0),
            (s("default"), s("192.0.2.5"), Advertised, Failed, 0),
        ]
    );
    let rows = &t[1].rows;
    assert_eq!(rows[2].next_hop, Some("192.0.2.3".parse().unwrap()));
    assert!(rows[1].best && !rows[2].best);
    assert!(
        t[3].detail
            .as_deref()
            .unwrap()
            .contains("totalPrefixCounter 3")
    );
}
