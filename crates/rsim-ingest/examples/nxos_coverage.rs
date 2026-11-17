//! Prints the coverage of an NX-OS running config, read from stdin. Each
//! line goes through the mask of the secrets.

use std::io::Read;

use rsim_ingest::{State, classify, nxos};

fn main() {
    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .expect("stdin is readable");
    let doc = nxos::read_text(&bytes);
    let cov = classify(&doc, &nxos::table(true));
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
