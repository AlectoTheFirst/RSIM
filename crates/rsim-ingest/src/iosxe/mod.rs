//! Cisco IOS-XE: the running config as indented text, and the collected
//! text sections through the TextFSM templates.

pub mod bgp;
pub mod bgp_config;
pub mod config;
mod layer2;
pub mod lower;
mod mask;
pub mod ospf_config;
mod profile;
pub mod state;
mod table;

use std::collections::BTreeSet;

use crate::coverage::Table;
use crate::stanza::{Document, read_indented};
pub use config::{Config, read};
pub use lower::{interface_states, lower};
pub use mask::mask;
pub use ospf_config::router_config;
pub use profile::profile;
pub use state::rib_vrfs;
pub use table::{dynamic_vrfs, table};

/// The text sections of a router or a switch that the lowering reads.
pub const SECTIONS: &[&str] = &[
    "interfaces",
    "rib",
    "rib_global",
    "arp",
    "acls",
    "lldp",
    "cdp",
    "hsrp",
    "vrrp",
    "mac_table",
    "spanning_tree",
    "vlans",
    "hsrp_detail",
    "vrrp_detail",
    "arp_vrfs",
];

pub use profile::INTERFACE_TYPES;

/// The resolver of the interface names of the sections to the names of the
/// config.
pub fn names(cfg: &Config) -> crate::nxos::names::Names {
    crate::nxos::names::Names::with_types(
        profile::INTERFACE_TYPES,
        cfg.interfaces.iter().map(|i| i.name.as_str()),
    )
}

/// Reads the bytes of a running config into a stanza tree. A byte sequence
/// that is not UTF-8 becomes the replacement character. The text lines of a
/// banner are children of its `banner` stanza.
pub fn read_text(bytes: &[u8]) -> Document {
    read_indented(&nest_banners(&String::from_utf8_lossy(bytes)))
}

/// The text with each line of the body of a banner indented by 1 space, so
/// that the stanza reader puts it below its `banner` line. The body runs
/// from the line after `banner <kind> <delimiter>` to the next line that
/// holds the delimiter. The delimiter is `^C`, as a running config shows
/// it, or else the first character after the kind. A banner that ends on
/// its own line, and a banner with no line that holds its delimiter, leave
/// the text unchanged. Each line keeps its number.
fn nest_banners(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut body = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if let Some(delim) = open_banner(lines[i])
            && let Some(end) = (i + 1..lines.len()).find(|&j| lines[j].contains(delim.as_str()))
        {
            for b in &mut body[i + 1..=end] {
                *b = true;
            }
            i = end;
        }
        i += 1;
    }
    let mut out = String::with_capacity(text.len() + lines.len());
    for (line, inside) in lines.iter().zip(body) {
        if inside {
            out.push(' ');
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The delimiter of a banner line whose body goes on below it, or `None`
/// for another line and for a banner that ends on its own line.
fn open_banner(line: &str) -> Option<String> {
    let rest = line.strip_prefix("banner ")?;
    let (_kind, text) = rest.split_once(' ')?;
    let text = text.trim_start();
    let delim: String = if text.starts_with("^C") {
        "^C".into()
    } else {
        text.chars().next()?.to_string()
    };
    (!text[delim.len()..].contains(delim.as_str())).then_some(delim)
}

/// The paths of the handled stanzas that no handler read, each key through
/// the mask. A correct handler set gives an empty list.
pub fn unread(doc: &Document, table: &Table, read: &BTreeSet<u32>) -> Vec<String> {
    crate::coverage::unread(doc, table, read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top(text: &str) -> Vec<String> {
        read_text(text.as_bytes())
            .root
            .children()
            .iter()
            .map(|s| s.key.clone())
            .collect()
    }

    #[test]
    fn the_lines_of_a_banner_are_below_it() {
        let text = "hostname r1\nbanner exec ^C\nAuthorized access only.\n\n! no comment\nSecond line\n^C\nbanner motd ^COne line.^C\nline vty 0 4\n";
        assert_eq!(
            top(text),
            [
                "hostname r1",
                "banner exec ^C",
                "banner motd ^COne line.^C",
                "line vty 0 4"
            ]
        );
        let doc = read_text(text.as_bytes());
        let b = doc.root.get("banner exec ^C").unwrap();
        assert_eq!((b.first_line, b.last_line), (2, 7));
        let kids: Vec<&str> = b.children().iter().map(|c| c.key.as_str()).collect();
        assert_eq!(kids, ["Authorized access only.", "Second line", "^C"]);
        assert_eq!(doc.lines, 9);
    }

    #[test]
    fn another_delimiter_and_a_text_after_the_delimiter() {
        let text = "banner login #Welcome\nto r1#\nend\n";
        assert_eq!(top(text), ["banner login #Welcome", "end"]);
    }

    #[test]
    fn a_banner_with_no_end_changes_nothing() {
        let text =
            "banner motd ^C\nhello\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n";
        assert_eq!(
            top(text),
            ["banner motd ^C", "hello", "interface Loopback0"]
        );
        assert_eq!(read_text(text.as_bytes()).lines, 4);
    }
}
