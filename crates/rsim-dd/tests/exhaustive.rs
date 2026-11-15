//! Each operation on widths up to 16 bits, compared with an explicit set of
//! all values.

mod common;

use common::*;
use proptest::prelude::*;
use rsim_dd::{Dd, Edge};

/// A truth table: entry `i` is the value for the assignment where level `l`
/// is bit `l` of `i`.
type Tt = Vec<bool>;

fn bit(i: usize, l: u32) -> bool {
    i >> l & 1 == 1
}

/// The function of a truth table, built with `ite` from the top level.
fn build_tt(dd: &mut Dd, tt: &Tt, n: u32) -> Edge {
    fn rec(dd: &mut Dd, tt: &Tt, n: u32, level: u32, idx: usize) -> Edge {
        if level == n {
            return if tt[idx] { Edge::TRUE } else { Edge::FALSE };
        }
        let lo = rec(dd, tt, n, level + 1, idx);
        let hi = rec(dd, tt, n, level + 1, idx | 1 << level);
        let v = dd.var(level).unwrap();
        dd.ite(v, hi, lo).unwrap()
    }
    rec(dd, tt, n, 0, 0)
}

/// The truth table of a function.
fn table(dd: &Dd, f: Edge, n: u32) -> Tt {
    (0..1usize << n)
        .map(|i| dd.eval(f, |l| bit(i, l)).unwrap())
        .collect()
}

fn count(tt: &Tt) -> u128 {
    tt.iter().filter(|b| **b).count() as u128
}

fn tables(n: u32) -> impl Strategy<Value = (Tt, Tt, Tt)> {
    let t = || prop::collection::vec(any::<bool>(), 1usize << n);
    (t(), t(), t())
}

fn case() -> impl Strategy<Value = (u32, Tt, Tt, Tt, Vec<u32>, Vec<u32>)> {
    (1u32..=8).prop_flat_map(|n| {
        let perm: Vec<u32> = (0..n).collect();
        (
            Just(n),
            tables(n),
            levels(n, n as usize),
            Just(perm).prop_shuffle(),
        )
            .prop_map(|(n, (a, b, c), q, p)| (n, a, b, c, q, p))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn each_operation_agrees_with_the_explicit_set((n, ta, tb, tc, quant, perm) in case()) {
        let mut dd = Dd::new(n);
        let a = build_tt(&mut dd, &ta, n);
        let b = build_tt(&mut dd, &tb, n);
        let c = build_tt(&mut dd, &tc, n);
        prop_assert_eq!(table(&dd, a, n), ta.clone());
        let size = 1usize << n;
        let each = |f: &dyn Fn(usize) -> bool| -> Tt { (0..size).map(f).collect() };

        let r = dd.and(a, b).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ta[i] && tb[i]));
        let r = dd.or(a, b).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ta[i] || tb[i]));
        let r = dd.xor(a, b).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ta[i] != tb[i]));
        let r = dd.diff(a, b).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ta[i] && !tb[i]));
        prop_assert_eq!(table(&dd, a.not(), n), each(&|i| !ta[i]));
        let r = dd.ite(a, b, c).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| if ta[i] { tb[i] } else { tc[i] }));

        let mask: usize = quant.iter().map(|l| 1usize << l).sum();
        let ex = |t: &Tt, i: usize| (0..size).any(|j| j & !mask == i & !mask && t[j]);
        let cube = dd.cube(&quant).unwrap();
        let r = dd.exists(a, cube).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ex(&ta, i)));
        let ab: Tt = each(&|i| ta[i] && tb[i]);
        let r = dd.and_exists(a, b, cube).unwrap();
        prop_assert_eq!(table(&dd, r, n), each(&|i| ex(&ab, i)));

        // The variable at level l moves to level perm[l], so the new function
        // reads level perm[l] where the old one read level l.
        let pairs: Vec<(u32, u32)> = (0..n).map(|l| (l, perm[l as usize])).collect();
        let m = dd.map(&pairs).unwrap();
        let r = dd.rename(a, m).unwrap();
        let moved = |i: usize| -> usize {
            (0..n).filter(|&l| bit(i, perm[l as usize])).map(|l| 1usize << l).sum()
        };
        prop_assert_eq!(table(&dd, r, n), each(&|i| ta[moved(i)]));

        prop_assert_eq!(dd.sat_count(a).unwrap(), count(&ta));
        prop_assert_eq!(dd.sat_count(a.not()).unwrap(), size as u128 - count(&ta));
        match dd.pick_one(a).unwrap() {
            None => prop_assert_eq!(count(&ta), 0),
            Some(path) => {
                let i: usize = path.iter().filter(|(_, v)| *v).map(|(l, _)| 1usize << l).sum();
                prop_assert!(ta[i]);
            }
        }
        dd.validate().unwrap();
    }
}

fn formula_case(n: u32) -> impl Strategy<Value = F> {
    formula(n, 6)
}

fn check_formula(n: u32, f: &F) -> Result<(), TestCaseError> {
    let mut dd = Dd::new(n);
    let e = build(&mut dd, f).unwrap();
    let mut ones = 0u128;
    for i in 0..1usize << n {
        let want = eval(f, &|l| bit(i, l));
        prop_assert_eq!(dd.eval(e, |l| bit(i, l)).unwrap(), want, "assignment {}", i);
        ones += u128::from(want);
    }
    prop_assert_eq!(dd.sat_count(e).unwrap(), ones);
    dd.validate().unwrap();
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn formulas_on_12_levels_agree_with_the_explicit_set(f in formula_case(12)) {
        check_formula(12, &f)?;
    }

    #[test]
    fn formulas_on_16_levels_agree_with_the_explicit_set(f in formula_case(16)) {
        check_formula(16, &f)?;
    }
}
