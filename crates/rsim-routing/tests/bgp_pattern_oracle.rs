//! The AS-path pattern matcher against a backtracking matcher written in
//! the test, over each AS path up to length 4 from a small alphabet.

use rsim_routing::bgp::{AsPath, AsPathLine, AsPathTerm, AsSegment, Asn, Pattern, SegmentKind};

enum R {
    Byte(Box<dyn Fn(u8) -> bool>),
    Start,
    End,
    Under,
    Cat(Vec<R>),
    Alt(Vec<R>),
    Star(Box<R>),
    Plus(Box<R>),
    Opt(Box<R>),
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn alt(&mut self) -> R {
        let mut v = vec![self.cat()];
        while self.s.get(self.i) == Some(&b'|') {
            self.i += 1;
            v.push(self.cat());
        }
        R::Alt(v)
    }

    fn cat(&mut self) -> R {
        let mut v = Vec::new();
        while let Some(&c) = self.s.get(self.i) {
            if c == b'|' || c == b')' {
                break;
            }
            let mut atom = self.atom();
            while let Some(&q) = self.s.get(self.i) {
                atom = match q {
                    b'*' => R::Star(Box::new(atom)),
                    b'+' => R::Plus(Box::new(atom)),
                    b'?' => R::Opt(Box::new(atom)),
                    _ => break,
                };
                self.i += 1;
            }
            v.push(atom);
        }
        R::Cat(v)
    }

    fn atom(&mut self) -> R {
        let c = self.s[self.i];
        self.i += 1;
        match c {
            b'.' => R::Byte(Box::new(|_| true)),
            b'^' => R::Start,
            b'$' => R::End,
            b'_' => R::Under,
            b'(' => {
                let r = self.alt();
                assert_eq!(self.s[self.i], b')');
                self.i += 1;
                r
            }
            b'[' => {
                let neg = self.s[self.i] == b'^';
                if neg {
                    self.i += 1;
                }
                let mut set = Vec::new();
                while self.s[self.i] != b']' {
                    let lo = self.s[self.i];
                    if self.s[self.i + 1] == b'-' {
                        set.push((lo, self.s[self.i + 2]));
                        self.i += 3;
                    } else {
                        set.push((lo, lo));
                        self.i += 1;
                    }
                }
                self.i += 1;
                R::Byte(Box::new(move |b| {
                    set.iter().any(|&(l, h)| l <= b && b <= h) != neg
                }))
            }
            c => R::Byte(Box::new(move |b| b == c)),
        }
    }
}

/// True if `r` matches `s` from `i` and `k` accepts the end position.
fn m(r: &R, s: &[u8], i: usize, k: &dyn Fn(usize) -> bool) -> bool {
    match r {
        R::Byte(f) => i < s.len() && f(s[i]) && k(i + 1),
        R::Start => i == 0 && k(i),
        R::End => i == s.len() && k(i),
        R::Under => {
            (i == 0 && k(i))
                || (i == s.len() && k(i))
                || (i < s.len() && b" ,{}()".contains(&s[i]) && k(i + 1))
        }
        R::Cat(v) => cat(v, s, i, k),
        R::Alt(v) => v.iter().any(|r| m(r, s, i, k)),
        R::Star(inner) => k(i) || star_after(inner, s, i, k),
        R::Plus(inner) => m(inner, s, i, &|j| k(j) || star_after(inner, s, j, k)),
        R::Opt(inner) => k(i) || m(inner, s, i, k),
    }
}

/// One or more further matches of `inner` from `i`, each of which moves
/// on, and then `k`.
fn star_after(inner: &R, s: &[u8], i: usize, k: &dyn Fn(usize) -> bool) -> bool {
    m(inner, s, i, &|j| {
        j > i && (k(j) || star_after(inner, s, j, k))
    })
}

fn cat(v: &[R], s: &[u8], i: usize, k: &dyn Fn(usize) -> bool) -> bool {
    match v.split_first() {
        None => k(i),
        Some((first, rest)) => m(first, s, i, &|j| cat(rest, s, j, k)),
    }
}

fn reference(pattern: &str, text: &str) -> bool {
    let mut p = P {
        s: pattern.as_bytes(),
        i: 0,
    };
    let r = p.alt();
    assert_eq!(p.i, pattern.len(), "{pattern}");
    (0..=text.len()).any(|i| m(&r, text.as_bytes(), i, &|_| true))
}

const PATTERNS: &[&str] = &[
    "",
    "^$",
    "^1$",
    "1",
    "_1_",
    "_12_",
    "^1_",
    "_2$",
    "^1 2$",
    "^(1 )*2$",
    "^(1|2)$",
    "^(1|12)_",
    "_(1|2)+_",
    "^[12]+$",
    "^[0-1]$",
    "^[^1]",
    "^.*$",
    "^. .$",
    "1.?2",
    "2?1",
    "^1+ 2",
    "_1 2_",
    "(_1)+$",
    "^(1 2 )?12$",
    "^((1|2) )+12$",
    "^(1( 2)*)?$",
    "^[1-2][2]?$",
    "^12|^21",
    "(1 1 1|2 2)",
    "^(.)*1$",
    "^((_1)|(_2))*$",
    "1*",
    "^(1*)*$",
    "_ _",
    "^(2|)$",
];

const UNHANDLED: &[&str] = &[
    "1{2}", "\\d", "[1", "(1", "1)", "a", "1**", "^*", "[]", "_{1,2}_x",
];

fn all_paths() -> Vec<AsPath> {
    let alphabet = [1u32, 2, 12];
    let mut out = vec![AsPath::default()];
    let mut level: Vec<Vec<u32>> = vec![vec![]];
    for _ in 0..4 {
        let mut next = Vec::new();
        for p in &level {
            for &a in &alphabet {
                let mut q = p.clone();
                q.push(a);
                next.push(q);
            }
        }
        out.extend(next.iter().map(|p| AsPath::sequence(p.as_slice())));
        level = next;
    }
    let seg = |kind, asns: &[u32]| AsSegment {
        kind,
        asns: asns.iter().map(|&a| Asn(a)).collect(),
    };
    for segments in [
        vec![seg(SegmentKind::Set, &[1, 2])],
        vec![
            seg(SegmentKind::Sequence, &[1]),
            seg(SegmentKind::Set, &[2, 12]),
        ],
        vec![
            seg(SegmentKind::ConfedSequence, &[1, 2]),
            seg(SegmentKind::Sequence, &[12]),
        ],
        vec![
            seg(SegmentKind::ConfedSet, &[1, 2]),
            seg(SegmentKind::Sequence, &[1]),
        ],
    ] {
        out.push(AsPath { segments });
    }
    out
}

#[test]
fn the_pattern_matcher_agrees_with_the_backtracking_matcher_on_each_short_path() {
    let paths = all_paths();
    assert_eq!(paths.len(), 1 + 3 + 9 + 27 + 81 + 4);
    let mut matched = 0;
    for &p in PATTERNS {
        let pattern = Pattern::parse(p).unwrap_or_else(|e| panic!("{e}"));
        for path in &paths {
            let text = path.to_string();
            let want = reference(p, &text);
            assert_eq!(pattern.is_match(&text), want, "{p:?} on {text:?}");
            matched += usize::from(want);
        }
    }
    assert!(matched > 500);
}

#[test]
fn a_pattern_outside_the_subset_gives_an_unhandled_line() {
    for &p in UNHANDLED {
        let line = AsPathLine::regex(10, true, p);
        assert_eq!(line.term, AsPathTerm::Unhandled(p.to_string()), "{p}");
        assert_eq!(line.matches(&AsPath::sequence(&[1])), None);
    }
}

#[test]
fn the_text_form_of_each_segment_kind() {
    let paths = all_paths();
    let texts: Vec<String> = paths[paths.len() - 4..]
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(texts, ["{1,2}", "1 {2,12}", "(1 2) 12", "[1,2] 1"]);
}

#[test]
fn the_underscore_does_not_match_inside_an_asn() {
    let line = AsPathLine::regex(10, true, "_64512_");
    assert_eq!(line.matches(&AsPath::sequence(&[64512])), Some(true));
    assert_eq!(
        line.matches(&AsPath::sequence(&[3356, 64512, 1])),
        Some(true)
    );
    assert_eq!(line.matches(&AsPath::sequence(&[645120])), Some(false));
}
