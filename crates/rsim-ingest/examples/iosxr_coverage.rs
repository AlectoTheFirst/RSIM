//! Prints the coverage of an IOS-XR running config, read from stdin. Each
//! line goes through the mask of the secrets.

use std::io::Read;

use rsim_ingest::route_tables::RouteTables;
use rsim_ingest::{State, classify, iosxr};

fn main() {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .expect("stdin is readable");
    let doc = iosxr::read_text(&bytes);
    let table = iosxr::table(&RouteTables::uniform(true, iosxr::dynamic_vrfs(&doc)));
    let cov = classify(&doc, &table);
    for state in [State::Handled, State::Irrelevant, State::Unhandled] {
        println!(
            "{state:?}: {} lines, {:.1} %",
            cov.lines.get(&state).copied().unwrap_or(0),
            100.0 * cov.share(state)
        );
    }
    for (path, stanzas, lines) in cov.ranked() {
        println!("  {stanzas:4} stanzas {lines:5} lines  {path}");
    }
    let cfg = iosxr::read(&doc, &table);
    for path in iosxr::unread(&doc, &table, &cfg.read) {
        println!("unread: {path}");
    }
}
