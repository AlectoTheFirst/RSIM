//! Lowers a VyOS device of the newest snapshot of a store, builds its twin
//! and prints the coverage, the lowering notes and the twin size.
//!
//! Arguments: the data folder of `rsim-collect` and the device. With 5
//! more arguments, it runs a path query: the ingress interface, the source
//! address, the destination address, `tcp` or `udp`, and the destination
//! port.

use rsim_engine::TwinBuilder;
use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{State, classify, collected, read_json, vyos};
use rsim_store::{Keys, Store};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (data, device) = (&args[1], &args[2]);
    let keys = std::fs::read_to_string(format!("{data}/keys")).expect("the key file is readable");
    let store = Store::open(
        format!("{data}/store"),
        Keys::from_hex(&keys).expect("valid keys"),
    )
    .expect("the store opens");
    let snap = store
        .latest()
        .expect("the store reads")
        .expect("a snapshot exists");
    let m = &snap.devices[device.as_str()];
    let cfg_entry = m.section("config").expect("a config section");
    let blob = cfg_entry.blob.expect("the config has a blob");
    let bytes = store.read_blob(&blob).expect("the blob reads");
    let doc = read_json(&bytes).expect("the config is JSON");
    let col = collected::read(&store, &snap, device).expect("the tables read");
    let table = vyos::table(&RouteTables::new(
        col.routes.iter().map(|r| r.vrf.clone()),
        vyos::dynamic_vrfs(&doc),
    ));
    let cov = classify(&doc, &table);
    let cfg = vyos::read(&doc);
    println!("snapshot {}", snap.manifest.cycle);
    for s in [State::Handled, State::Irrelevant, State::Unhandled] {
        println!("{s:?}: {:.1} %", 100.0 * cov.share(s));
    }
    for (p, n, lines) in cov.ranked() {
        println!("  unhandled {n} stanzas {lines} lines {p}");
    }
    for p in vyos::unread(&doc, &table, &cfg.read) {
        println!("  handled but not read: {p}");
    }
    let file = format!("{device}/config@{}", &blob.to_string()[..12]);
    let low = vyos::lower(
        device,
        &file,
        &vyos::profile(),
        &cfg,
        &col,
        &Default::default(),
    );
    println!(
        "collected: {} addresses, {} routes, {} neighbours",
        col.addresses.len(),
        col.routes.len(),
        col.neighbours.len()
    );
    for n in &low.notes {
        println!("  note: {n}");
    }
    let mut b = TwinBuilder::new();
    let functions = low.functions.len();
    for f in low.functions {
        b.add_arc(f);
    }
    for e in low.edges {
        b.edge_interface(e);
    }
    match b.build() {
        Ok(t) => {
            println!(
                "twin: {} functions, {} devices",
                functions,
                t.device_count()
            );
            if args.len() == 8 {
                let proto = if args[6] == "tcp" { 6 } else { 17 };
                let h = rsim_core::Header::request(
                    args[4].parse().expect("a source address"),
                    args[5].parse().expect("a destination address"),
                    proto,
                )
                .with_src_port(40000)
                .with_dst_port(args[7].parse().expect("a port"));
                let q = rsim_engine::Query::path(&t, &h)
                    .with_ingress(device.as_str(), args[3].as_str());
                let a = rsim_engine::Executor::new(&t)
                    .run(&q)
                    .expect("the query runs");
                for b in a.branches() {
                    let path: Vec<String> = b
                        .steps
                        .iter()
                        .map(|s| format!("{} ({})", s.function, s.reason.detail))
                        .collect();
                    println!("path: {}", path.join("\n  -> "));
                    println!("verdict: {:?}", b.verdict);
                }
            }
        }
        Err(errors) => {
            for e in errors {
                println!("  build error: {e}");
            }
        }
    }
}
