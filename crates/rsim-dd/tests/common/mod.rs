//! Formulas for the tests: a direct evaluation, a build into a [`Dd`], and
//! the proptest generators.

#![allow(dead_code)]

use proptest::prelude::*;
use rsim_dd::{Dd, DdError, Edge};

/// A Boolean formula over variable levels.
#[derive(Clone, Debug)]
pub enum F {
    Const(bool),
    Var(u32),
    Not(Box<F>),
    And(Box<F>, Box<F>),
    Or(Box<F>, Box<F>),
    Xor(Box<F>, Box<F>),
    Diff(Box<F>, Box<F>),
    Ite(Box<F>, Box<F>, Box<F>),
    Exists(Box<F>, Vec<u32>),
    AndExists(Box<F>, Box<F>, Vec<u32>),
    /// Disjoint swaps of 2 levels.
    Rename(Box<F>, Vec<(u32, u32)>),
}

fn swap_of(swaps: &[(u32, u32)], l: u32) -> u32 {
    for &(a, b) in swaps {
        if l == a {
            return b;
        }
        if l == b {
            return a;
        }
    }
    l
}

/// The value of the formula for an assignment.
pub fn eval(f: &F, x: &dyn Fn(u32) -> bool) -> bool {
    match f {
        F::Const(b) => *b,
        F::Var(l) => x(*l),
        F::Not(a) => !eval(a, x),
        F::And(a, b) => eval(a, x) && eval(b, x),
        F::Or(a, b) => eval(a, x) || eval(b, x),
        F::Xor(a, b) => eval(a, x) != eval(b, x),
        F::Diff(a, b) => eval(a, x) && !eval(b, x),
        F::Ite(c, a, b) => {
            if eval(c, x) {
                eval(a, x)
            } else {
                eval(b, x)
            }
        }
        F::Exists(a, ls) => exists_eval(ls, x, &|y| eval(a, y)),
        F::AndExists(a, b, ls) => exists_eval(ls, x, &|y| eval(a, y) && eval(b, y)),
        F::Rename(a, swaps) => eval(a, &|l| x(swap_of(swaps, l))),
    }
}

/// An assignment of the variable levels.
pub type Assign<'a> = &'a dyn Fn(u32) -> bool;

fn exists_eval(ls: &[u32], x: Assign, f: &dyn Fn(Assign) -> bool) -> bool {
    let mut ls = ls.to_vec();
    ls.sort_unstable();
    ls.dedup();
    (0..1u32 << ls.len()).any(|bits| {
        let y = |l: u32| match ls.iter().position(|&q| q == l) {
            Some(i) => bits >> i & 1 == 1,
            None => x(l),
        };
        f(&y)
    })
}

/// The formula as a function in the arena, built with the public operations.
pub fn build(dd: &mut Dd, f: &F) -> Result<Edge, DdError> {
    Ok(match f {
        F::Const(true) => Edge::TRUE,
        F::Const(false) => Edge::FALSE,
        F::Var(l) => dd.var(*l)?,
        F::Not(a) => build(dd, a)?.not(),
        F::And(a, b) => {
            let (a, b) = (build(dd, a)?, build(dd, b)?);
            dd.and(a, b)?
        }
        F::Or(a, b) => {
            let (a, b) = (build(dd, a)?, build(dd, b)?);
            dd.or(a, b)?
        }
        F::Xor(a, b) => {
            let (a, b) = (build(dd, a)?, build(dd, b)?);
            dd.xor(a, b)?
        }
        F::Diff(a, b) => {
            let (a, b) = (build(dd, a)?, build(dd, b)?);
            dd.diff(a, b)?
        }
        F::Ite(c, a, b) => {
            let (c, a, b) = (build(dd, c)?, build(dd, a)?, build(dd, b)?);
            dd.ite(c, a, b)?
        }
        F::Exists(a, ls) => {
            let a = build(dd, a)?;
            let c = dd.cube(ls)?;
            dd.exists(a, c)?
        }
        F::AndExists(a, b, ls) => {
            let (a, b) = (build(dd, a)?, build(dd, b)?);
            let c = dd.cube(ls)?;
            dd.and_exists(a, b, c)?
        }
        F::Rename(a, swaps) => {
            let a = build(dd, a)?;
            let pairs: Vec<(u32, u32)> =
                swaps.iter().flat_map(|&(x, y)| [(x, y), (y, x)]).collect();
            let m = dd.map(&pairs)?;
            dd.rename(a, m)?
        }
    })
}

/// Disjoint swaps of levels below `n`.
pub fn swaps(n: u32) -> impl Strategy<Value = Vec<(u32, u32)>> {
    swaps_in((0..n).collect())
}

/// Disjoint swaps of levels from `pool`.
pub fn swaps_in(pool: Vec<u32>) -> impl Strategy<Value = Vec<(u32, u32)>> {
    let k = pool.len().min(6);
    prop::sample::subsequence(pool, 0..=k)
        .prop_shuffle()
        .prop_map(|v| v.as_chunks::<2>().0.iter().map(|c| (c[0], c[1])).collect())
}

/// Up to `k` levels below `n`.
pub fn levels(n: u32, k: usize) -> impl Strategy<Value = Vec<u32>> {
    levels_in((0..n).collect(), k)
}

/// Up to `k` levels from `pool`.
pub fn levels_in(pool: Vec<u32>, k: usize) -> impl Strategy<Value = Vec<u32>> {
    let k = k.min(pool.len());
    prop::sample::subsequence(pool, 0..=k)
}

/// Formulas over the levels below `n`, with constants and variables as
/// leaves.
pub fn formula(n: u32, depth: u32) -> impl Strategy<Value = F> {
    let leaf = prop_oneof![
        1 => any::<bool>().prop_map(F::Const),
        6 => (0..n).prop_map(F::Var),
    ];
    formula_with(leaf.boxed(), (0..n).collect(), depth)
}

/// Formulas with the given leaves. The quantified levels and the swaps come
/// from `pool`.
pub fn formula_with(
    leaf: BoxedStrategy<F>,
    pool: Vec<u32>,
    depth: u32,
) -> impl Strategy<Value = F> {
    leaf.prop_recursive(depth, 64, 3, move |inner| {
        prop_oneof![
            2 => inner.clone().prop_map(|a| F::Not(Box::new(a))),
            3 => (inner.clone(), inner.clone()).prop_map(|(a, b)| F::And(Box::new(a), Box::new(b))),
            3 => (inner.clone(), inner.clone()).prop_map(|(a, b)| F::Or(Box::new(a), Box::new(b))),
            2 => (inner.clone(), inner.clone()).prop_map(|(a, b)| F::Xor(Box::new(a), Box::new(b))),
            2 => (inner.clone(), inner.clone()).prop_map(|(a, b)| F::Diff(Box::new(a), Box::new(b))),
            1 => (inner.clone(), inner.clone(), inner.clone())
                .prop_map(|(c, a, b)| F::Ite(Box::new(c), Box::new(a), Box::new(b))),
            1 => (inner.clone(), levels_in(pool.clone(), 3)).prop_map(|(a, ls)| F::Exists(Box::new(a), ls)),
            1 => (inner.clone(), inner.clone(), levels_in(pool.clone(), 3))
                .prop_map(|(a, b, ls)| F::AndExists(Box::new(a), Box::new(b), ls)),
            1 => (inner, swaps_in(pool.clone())).prop_map(|(a, s)| F::Rename(Box::new(a), s)),
        ]
    })
}
