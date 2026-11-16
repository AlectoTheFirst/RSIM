//! Prints the coverage of a VyOS configuration in JSON form, read from
//! stdin.

use std::io::Read;

use rsim_ingest::{State, classify, read_json, vyos};

fn main() {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .expect("stdin is readable");
    let doc = read_json(&bytes).expect("stdin is a JSON configuration");
    let cov = classify(&doc, &vyos::table(true));
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
}
