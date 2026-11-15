//! Operations on sets of address prefixes on the full header width.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rsim_dd::{Dd, Edge};

const BITS: u32 = 763;
const LEVELS: u32 = BITS * 3;
/// The first header bit of the destination address in the bit table.
const DST_IP: u32 = 5 + 11 + 1 + 8;

/// A root arena with no shadow check.
fn root() -> Dd {
    let mut dd = Dd::new(LEVELS);
    dd.set_shadow(false);
    dd
}

/// A scratch arena with no shadow check.
fn scratch(frozen: &std::sync::Arc<rsim_dd::Frozen>) -> Dd {
    let mut dd = Dd::scratch(frozen.clone(), Some(1_000_000));
    dd.set_shadow(false);
    dd
}

/// A fixed sequence of numbers for the test data.
struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// The set of headers whose destination address in level bank `bank` starts
/// with the `len` bits of `value`, with the most significant bit first.
fn prefix(dd: &mut Dd, value: u128, len: u32, bank: u32) -> Edge {
    let mut f = Edge::TRUE;
    for i in (0..len).rev() {
        let level = (DST_IP + i) * 3 + bank;
        let v = dd.var(level).unwrap();
        let lit = if value >> (127 - i) & 1 == 1 {
            v
        } else {
            v.not()
        };
        f = dd.and(lit, f).unwrap();
    }
    f
}

fn prefixes(dd: &mut Dd, seq: &mut Seq, count: usize) -> Vec<Edge> {
    (0..count)
        .map(|_| {
            let value = (u128::from(seq.next()) << 64) | u128::from(seq.next());
            let len = 8 + (seq.next() % 25) as u32;
            prefix(dd, value, len, 1)
        })
        .collect()
}

fn union(dd: &mut Dd, sets: &[Edge]) -> Edge {
    sets.iter()
        .fold(Edge::FALSE, |acc, &s| dd.or(acc, s).unwrap())
}

fn bench(c: &mut Criterion) {
    c.bench_function("union of 1000 prefixes", |b| {
        b.iter(|| {
            let mut dd = root();
            let ps = prefixes(&mut dd, &mut Seq(7), 1000);
            black_box(union(&mut dd, &ps))
        })
    });

    let mut root = root();
    let a = {
        let ps = prefixes(&mut root, &mut Seq(7), 1000);
        union(&mut root, &ps)
    };
    let b = {
        let ps = prefixes(&mut root, &mut Seq(11), 1000);
        union(&mut root, &ps)
    };
    let pairs: Vec<(u32, u32)> = (0..BITS)
        .flat_map(|bit| [(bit * 3 + 1, bit * 3 + 2), (bit * 3 + 2, bit * 3 + 1)])
        .collect();
    let bank: Vec<u32> = (0..BITS).map(|bit| bit * 3 + 1).collect();
    let frozen = root.freeze().unwrap();

    c.bench_function(
        "intersect 2 unions of 1000 prefixes, scratch arena",
        |bch| {
            bch.iter(|| {
                let mut dd = scratch(&frozen);
                black_box(dd.and(a, b).unwrap())
            })
        },
    );
    c.bench_function(
        "difference of 2 unions of 1000 prefixes, scratch arena",
        |bch| {
            bch.iter(|| {
                let mut dd = scratch(&frozen);
                black_box(dd.diff(a, b).unwrap())
            })
        },
    );
    c.bench_function(
        "rename a union of 1000 prefixes to the work levels",
        |bch| {
            bch.iter(|| {
                let mut dd = scratch(&frozen);
                let m = dd.map(&pairs).unwrap();
                black_box(dd.rename(a, m).unwrap())
            })
        },
    );
    c.bench_function("exists over the current levels of a union", |bch| {
        bch.iter(|| {
            let mut dd = scratch(&frozen);
            let cube = dd.cube(&bank).unwrap();
            black_box(dd.exists(a, cube).unwrap())
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
