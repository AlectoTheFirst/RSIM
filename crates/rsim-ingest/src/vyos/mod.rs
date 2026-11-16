//! VyOS 1.4 and 1.5.

pub mod config;
pub mod lower;
mod profile;
mod table;

use std::collections::BTreeSet;

use crate::coverage::{State, Table};
use crate::stanza::{Document, Stanza};
pub use config::{Config, read};
pub use lower::{Lowered, lower};
pub use profile::profile;
pub use table::table;

/// The paths of the handled stanzas that no handler read. A correct handler
/// set gives an empty list.
pub fn unread(doc: &Document, table: &Table, read: &BTreeSet<u32>) -> Vec<String> {
    let mut out = Vec::new();
    let mut path = Vec::new();
    for c in doc.root.children() {
        walk(c, table, read, &mut path, &mut out);
    }
    out
}

fn walk<'a>(
    s: &'a Stanza,
    table: &Table,
    read: &BTreeSet<u32>,
    path: &mut Vec<&'a str>,
    out: &mut Vec<String>,
) {
    path.push(&s.key);
    let state = table.state(path);
    if state == State::Handled && !read.contains(&s.first_line) {
        out.push(path.join("/"));
    }
    if state != State::Unhandled {
        for c in s.children() {
            walk(c, table, read, path, out);
        }
    }
    path.pop();
}
