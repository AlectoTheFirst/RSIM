//! Writes a store with the synthetic VyOS router `r1` and the synthetic
//! UniFi site `site1` of `rsim-ingest`, for the tests of `rsim` and
//! `rsim-mcp`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rsim_store::{
    Cell, Class, DeviceUpdate, Entropy, Format, Hash, Keys, Row, SectionEntry, SectionStatus, Store,
};

struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
    }
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

/// Writes the data folder of `rsim-collect` in `dir`: the store keys in
/// `keys` and the store in `store`, with one snapshot.
#[allow(clippy::disallowed_methods)]
pub fn write(dir: &Path) {
    let hash = [1u8; 32];
    let wrap = [2u8; 32];
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("keys"),
        format!("{}\n{}\n", hex(&hash), hex(&wrap)),
    )
    .unwrap();
    let store = Store::open(dir.join("store"), Keys::new(hash, wrap)).unwrap();
    let mut e = Counter(0);
    let mut put = |b: &[u8]| store.put_blob(b, &mut e).unwrap();

    let config = put(&fixture("vyos/r1-config.json"));
    let routes = put(b"routes");
    let links = put(b"links");
    let addresses = put(b"addresses");
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
            Cell::Null,
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
    };
    let mut c = store.begin(1).unwrap();
    c.add(r1).unwrap();
    c.add(site).unwrap();
    c.prepare()
        .unwrap()
        .expect("the cycle has changes")
        .publish()
        .unwrap();
}
