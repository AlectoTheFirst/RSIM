//! The prefix lists against a second matcher over each prefix of small
//! IPv4 and IPv6 spaces. The second matcher compares the prefixes as bit
//! strings.

mod bgp_common;

use bgp_common::{Rng, pfx};
use rsim_core::Prefix;
use rsim_routing::bgp::{PrefixList, PrefixListEntry};

/// The first `len` bits of a prefix as a string of `0` and `1`.
fn bits(p: Prefix) -> String {
    (0..p.len())
        .map(|i| if p.bit(i) { '1' } else { '0' })
        .collect()
}

/// One line as the vendor writes it.
#[derive(Clone, Copy, Debug)]
struct Line {
    seq: u32,
    permit: bool,
    prefix: Prefix,
    ge: Option<u8>,
    le: Option<u8>,
    eq: Option<u8>,
}

/// The length range of a line, written out case by case.
fn range(l: &Line) -> (u8, u8) {
    let base = l.prefix.len();
    let top = if l.prefix.is_ipv4() { 32 } else { 128 };
    match (l.ge, l.le, l.eq) {
        (_, _, Some(eq)) => (eq, eq),
        (None, None, None) => (base, base),
        (Some(ge), None, None) => (ge, top),
        (None, Some(le), None) => (base, le),
        (Some(ge), Some(le), None) => (ge, le),
    }
}

fn oracle_line(l: &Line, c: Prefix) -> bool {
    let (lo, hi) = range(l);
    c.is_ipv4() == l.prefix.is_ipv4()
        && bits(c).starts_with(&bits(l.prefix))
        && lo <= c.len()
        && c.len() <= hi
}

fn oracle(lines: &[Line], c: Prefix) -> bool {
    let mut sorted = lines.to_vec();
    sorted.sort_by_key(|l| l.seq);
    for l in &sorted {
        if oracle_line(l, c) {
            return l.permit;
        }
    }
    false
}

fn list(lines: &[Line]) -> PrefixList {
    PrefixList::new(
        lines
            .iter()
            .map(|l| PrefixListEntry::new(l.seq, l.permit, l.prefix, l.ge, l.le, l.eq))
            .collect(),
    )
}

/// Each prefix inside `base` with a length up to `base` plus `depth`.
fn space(base: &str, depth: u8) -> Vec<Prefix> {
    let base = pfx(base);
    let mut out = vec![base];
    let mut level = vec![base];
    for _ in 0..depth {
        let mut next = Vec::new();
        for p in &level {
            let len = p.len() + 1;
            let low = Prefix::new(p.addr(), len);
            next.push(low);
            let high = match p.addr() {
                std::net::IpAddr::V4(a) => {
                    let v = u32::from(a) | (1u32 << (32 - u32::from(len)));
                    Prefix::new(std::net::Ipv4Addr::from(v).into(), len)
                }
                std::net::IpAddr::V6(a) => {
                    let v = u128::from(a) | (1u128 << (128 - u32::from(len)));
                    Prefix::new(std::net::Ipv6Addr::from(v).into(), len)
                }
            };
            next.push(high);
        }
        out.extend(next.iter().copied());
        level = next;
    }
    out
}

fn qualifiers(base: u8, top: u8) -> Vec<(Option<u8>, Option<u8>, Option<u8>)> {
    let mut out = Vec::new();
    let ges = [None, Some(base), Some(base + 1), Some(base + 3)];
    let les = [None, Some(base + 1), Some(base + 2), Some(top)];
    let eqs = [None, Some(base + 2)];
    for ge in ges {
        for le in les {
            for eq in eqs {
                out.push((ge, le, eq));
            }
        }
    }
    out
}

fn check_space(base: &str, top: u8, other: &[Prefix]) {
    let mut candidates = space(base, 5);
    candidates.extend_from_slice(other);
    let lines_prefixes: Vec<Prefix> = candidates
        .iter()
        .copied()
        .filter(|p| p.len() <= pfx(base).len() + 3)
        .collect();
    let mut cases = 0;
    for &prefix in &lines_prefixes {
        for (ge, le, eq) in qualifiers(prefix.len(), top) {
            for permit in [true, false] {
                let lines = [Line {
                    seq: 5,
                    permit,
                    prefix,
                    ge,
                    le,
                    eq,
                }];
                let l = list(&lines);
                for &c in &candidates {
                    assert_eq!(l.permits(c), oracle(&lines, c), "{lines:?} on {c}");
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 10_000);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..400 {
        let n = 1 + rng.below(4) as usize;
        let lines: Vec<Line> = (0..n)
            .map(|_| {
                let prefix = rng.pick(&lines_prefixes);
                let (ge, le, eq) = rng.pick(&qualifiers(prefix.len(), top));
                Line {
                    seq: rng.below(50) as u32,
                    permit: rng.below(2) == 0,
                    prefix,
                    ge,
                    le,
                    eq,
                }
            })
            .collect();
        let l = list(&lines);
        for &c in &candidates {
            assert_eq!(l.permits(c), oracle(&lines, c), "{lines:?} on {c}");
        }
    }
}

#[test]
fn ipv4_prefix_lists_with_ge_le_and_eq_agree_with_the_bit_string_matcher() {
    check_space(
        "192.0.0.0/22",
        32,
        &[
            pfx("198.51.100.0/24"),
            pfx("0.0.0.0/0"),
            pfx("2001:db8::/32"),
        ],
    );
}

#[test]
fn ipv6_prefix_lists_with_ge_le_and_eq_agree_with_the_bit_string_matcher() {
    check_space(
        "2001:db8::/32",
        128,
        &[pfx("2001:db9::/32"), pfx("::/0"), pfx("192.0.2.0/24")],
    );
}

#[test]
fn ge_alone_runs_to_128_on_an_ipv6_line() {
    let l = PrefixList::new(vec![PrefixListEntry::new(
        5,
        true,
        pfx("2001:db8::/32"),
        Some(48),
        None,
        None,
    )]);
    assert!(l.permits(pfx("2001:db8:1::/48")));
    assert!(l.permits(pfx("2001:db8:1::1/128")));
    assert!(!l.permits(pfx("2001:db8::/32")));
}

#[test]
fn an_ipv4_line_matches_no_ipv6_prefix() {
    let l = PrefixList::new(vec![PrefixListEntry::new(
        5,
        true,
        pfx("0.0.0.0/0"),
        None,
        Some(32),
        None,
    )]);
    assert!(l.permits(pfx("192.0.2.0/24")));
    assert!(!l.permits(pfx("2001:db8::/32")));
}
