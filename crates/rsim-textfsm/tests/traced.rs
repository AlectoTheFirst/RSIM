//! The input lines of each record and the lines that no record holds.

use rsim_textfsm::{Library, Template};

fn route_template() -> Template {
    let lib = Library::builtin().unwrap();
    lib.find("cisco_xr", "show route vrf all ipv4")
        .unwrap()
        .1
        .clone()
}

#[test]
fn the_traced_parse_gives_the_records_of_parse_text() {
    let t = route_template();
    let input = include_str!("fixtures/conformance/cisco_xr_show_ip_route/unread.txt");
    let traced = t.parse_traced(input).unwrap();
    assert_eq!(traced.table, t.parse_text(input).unwrap());
    assert_eq!(traced.lines.len(), traced.table.records.len());
}

#[test]
fn a_record_has_its_lines_and_a_discarded_record_is_unread() {
    let t = route_template();
    let input = "\
VRF: default

O    192.0.2.64/26 [110/20] via 198.51.100.6, 1d02h, Gi0/0/0/1
                   [110/20] via 198.51.100.10, 1d02h, Gi0/0/0/2
B    203.0.113.64/26 [1/0] via 2001:db8::1, 00:12:01
                   [1/0] via 2001:db8::2, 00:12:01
C    198.51.100.0/30 is directly connected, 3d04h, Gi0/0/0/0
VRF: RED
B    192.0.2.128/26
";
    let traced = t.parse_traced(input).unwrap();
    assert_eq!(traced.lines, [(3, 3), (4, 4), (7, 7)]);
    let unread: Vec<(usize, bool)> = traced
        .unread
        .iter()
        .map(|u| (u.line, u.unmatched))
        .collect();
    assert_eq!(unread, [(5, false), (6, false), (9, false)]);
    let vrf = traced.table.header.iter().position(|h| h == "VRF").unwrap();
    let net = traced
        .table
        .header
        .iter()
        .position(|h| h == "NETWORK")
        .unwrap();
    let u = &traced.unread[0];
    assert!(u.text.starts_with("B    203.0.113.64/26"));
    assert_eq!(u.values[vrf], "default");
    // The Filldown value of the line before.
    assert_eq!(traced.unread[1].values[net], "192.0.2.64");
    assert_eq!(traced.unread[2].values[vrf], "RED");
}

#[test]
fn a_line_that_no_rule_matches_is_unread() {
    let t = Template::parse("Value Required A (\\d+)\n\nStart\n  ^a ${A} -> Record\n  ^skip\n")
        .unwrap();
    let traced = t.parse_traced("a 1\nb 2\nskip\na 3\n").unwrap();
    assert_eq!(traced.lines, [(1, 1), (4, 4)]);
    let unread: Vec<(usize, &str, bool)> = traced
        .unread
        .iter()
        .map(|u| (u.line, u.text.as_str(), u.unmatched))
        .collect();
    assert_eq!(unread, [(2, "b 2", true)]);
}

#[test]
fn a_record_of_several_lines_spans_them() {
    let t = Template::parse(
        "Value Required NAME (\\S+)\nValue STATE (\\S+)\n\nStart\n  ^\\S+ is -> Continue.Record\n  ^${NAME} is ${STATE}\n  ^\\s+mtu\n",
    )
    .unwrap();
    let traced = t
        .parse_traced("e1 is up\n  mtu 1500\ne2 is down\n  mtu 9000\n")
        .unwrap();
    assert_eq!(traced.table.records.len(), 2);
    assert_eq!(traced.lines, [(1, 1), (3, 3)]);
}
