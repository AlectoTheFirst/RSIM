//! Builds the twin of the newest snapshot of a store and prints the coverage,
//! the lowering notes and the twin size of each device.
//!
//! Arguments: the data folder of `rsim-collect`. With 4 more arguments, it
//! runs a path query: the source address, the destination address, `tcp` or
//! `udp`, and the destination port. The ingress comes from the attachment
//! of the source address.

use rsim_ingest::{State, estate};
use rsim_store::{Keys, Store};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = &args[1];
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
    let e = estate::build(&store, &snap).expect("the snapshot reads");
    println!("snapshot {}", snap.manifest.cycle);
    for (device, cov) in &e.coverage {
        println!(
            "{device}: handled {:.1} %, irrelevant {:.1} %, unhandled {:.1} %",
            100.0 * cov.share(State::Handled),
            100.0 * cov.share(State::Irrelevant),
            100.0 * cov.share(State::Unhandled)
        );
        for (p, n, lines) in cov.ranked() {
            println!("  unhandled {n} stanzas {lines} lines {p}");
        }
        for p in e.unread.get(device).into_iter().flatten() {
            println!("  handled but not read: {p}");
        }
        for n in e.notes.get(device).into_iter().flatten() {
            println!("  note: {n}");
        }
    }
    let twin = match e.builder.build() {
        Ok(t) => t,
        Err(errors) => {
            for x in errors {
                println!("build error: {x}");
            }
            return;
        }
    };
    println!(
        "twin: {} functions, {} devices, {} endpoints",
        twin.function_count(),
        twin.device_count(),
        twin.endpoints().count()
    );
    if args.len() == 6 {
        let proto = if args[4] == "tcp" { 6 } else { 17 };
        let h = rsim_core::Header::request(
            args[2].parse().expect("a source address"),
            args[3].parse().expect("a destination address"),
            proto,
        )
        .with_src_port(40000)
        .with_dst_port(args[5].parse().expect("a port"));
        let a = rsim_engine::Executor::new(&twin)
            .run(&rsim_engine::Query::path(&twin, &h))
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
        println!("summary: {:?}", a.verdict());
    }
}
