//! Writes a store with the synthetic VyOS router `r1`, with its BGP session
//! and version sections, and the synthetic UniFi site `site1` of
//! `rsim-ingest`, for the tests of `rsim` and `rsim-mcp`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rsim_store::{
    Cell, Class, DeviceUpdate, Entropy, Format, Hash, Keys, Row, SectionEntry, SectionStatus, Store,
};

/// `N` random bytes from the operating system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

/// Random keys and nonces from the operating system.
pub struct Os;

impl Entropy for Os {
    fn key(&mut self) -> [u8; 32] {
        random()
    }
    fn nonce(&mut self) -> [u8; 24] {
        random()
    }
}

/// The keys of the data folder: those of its file `keys`, else new random
/// keys, which the file then holds.
#[allow(clippy::disallowed_methods)]
fn keys(dir: &Path) -> Keys {
    let path = dir.join("keys");
    if let Ok(text) = std::fs::read_to_string(&path) {
        return Keys::from_hex(&text).unwrap();
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let text = format!("{}\n{}\n", hex(&random::<32>()), hex(&random::<32>()));
    std::fs::write(&path, &text).unwrap();
    Keys::from_hex(&text).unwrap()
}

fn fixture(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rsim-ingest/tests/fixtures")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn entry(name: &str, blob: Hash, class: Class) -> SectionEntry {
    SectionEntry {
        name: name.into(),
        command: name.into(),
        class,
        format: Format::Json,
        change_hash: Some(blob),
        blob: Some(blob),
        status: SectionStatus::Fresh,
        collected_at: Some(1),
    }
}

fn s(v: &str) -> Cell {
    Cell::Str(v.into())
}

/// The time of the snapshot of a new store: 2026-11-22 14:05:12 UTC.
pub const TIME: u64 = 1_795_356_312_000;

/// Writes the data folder of `rsim-collect` in `dir`: the store keys in
/// `keys` and the store in `store`, with one snapshot at [`TIME`], or at the
/// second after the newest snapshot of a store that has one.
#[allow(clippy::disallowed_methods)]
pub fn write(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let store = Store::open(dir.join("store"), keys(dir)).unwrap();
    let mut e = Os;
    let mut put = |b: &[u8]| store.put_blob(b, &mut e).unwrap();

    let config = put(&fixture("vyos/r1-config.json"));
    let routes = put(b"routes");
    let links = put(b"links");
    let addresses = put(b"addresses");
    let sessions = put(&fixture("vyos/r1-bgp-sessions.json"));
    let version = put(&fixture("vyos/version.txt"));
    let route = |p: &str, proto: &str, i: &str| -> Row {
        vec![
            s("default"),
            s(p),
            s(proto),
            Cell::Bool(true),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            s(i),
        ]
    };
    let link = |i: &str, parent: Option<&str>| -> Row {
        vec![
            s(i),
            s("00:00:5e:00:53:01"),
            Cell::U64(1500),
            Cell::Bool(true),
            Cell::Null,
            parent.map_or(Cell::Null, s),
            Cell::Null,
        ]
    };
    let r1 = DeviceUpdate {
        device: "r1".into(),
        vendor: "vyos".into(),
        collected_at: 1,
        sections: vec![
            entry("config", config, Class::Configuration),
            entry("routes_ipv4", routes, Class::Observation),
            entry("links", links, Class::Observation),
            entry("addresses", addresses, Class::Observation),
            entry("bgp_sessions", sessions, Class::Observation),
            SectionEntry {
                format: Format::Text,
                ..entry("version", version, Class::Configuration)
            },
        ],
        tables: BTreeMap::from([
            (
                "routes".to_string(),
                vec![(
                    routes,
                    vec![
                        route("0.0.0.0/0", "kernel", "pppoe0"),
                        route("192.0.2.0/26", "connected", "eth0.10"),
                        route("192.0.2.64/26", "connected", "eth0.110"),
                        route("192.0.2.192/27", "connected", "eth0"),
                    ],
                )],
            ),
            (
                "links".to_string(),
                vec![(
                    links,
                    vec![
                        link("eth0", None),
                        link("eth0.10", Some("eth0")),
                        link("eth0.110", Some("eth0")),
                    ],
                )],
            ),
            (
                "addresses".to_string(),
                vec![(addresses, vec![vec![s("pppoe0"), s("203.0.113.10/32")]])],
            ),
        ]),
        management_address: Some("192.0.2.254".into()),
    };
    let mut sections = Vec::new();
    for name in ["networks", "wlans", "devices", "clients", "port_profiles"] {
        let b = put(&fixture(&format!("unifi/{name}.json")));
        sections.push(entry(name, b, Class::Configuration));
    }
    let site = DeviceUpdate {
        device: "site1".into(),
        vendor: "unifi".into(),
        collected_at: 1,
        sections,
        tables: BTreeMap::new(),
        management_address: Some("192.0.2.253".into()),
    };
    let newest = store.head_manifest().unwrap().map_or(0, |m| m.time);
    let mut c = store.begin(TIME.max(newest / 1000 * 1000 + 1000)).unwrap();
    c.add(r1).unwrap();
    c.add(site).unwrap();
    c.prepare()
        .unwrap()
        .expect("the cycle has changes")
        .publish()
        .unwrap();
}
