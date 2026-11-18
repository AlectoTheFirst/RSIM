//! The OxiDD oracle: the same operations in OxiDD on the full header width,
//! compared by set.

mod common;

use std::collections::HashMap;

use common::*;
use oxidd::bdd::BDDFunction;
use oxidd::util::AllocResult;
use oxidd::{BooleanFunction, BooleanFunctionQuant, FunctionSubst, Manager, ManagerRef};
use proptest::prelude::*;
use rsim_dd::{Dd, Edge};

/// The header bits of the bit table.
const BITS: u32 = 764;
/// Each bit has 4 levels: the original request, the current header, the
/// work level and the inner level.
const LEVELS: u32 = BITS * 4;

/// A field constraint: the bits from `start` have the value `value` in one
/// of the 4 levels of each bit, as a prefix of `len` bits.
fn prefix(start: u32, len: u32, value: u32, bank: u32) -> F {
    let mut f = F::Const(true);
    for i in 0..len {
        let v = F::Var((start + i) * 4 + bank);
        let lit = if value >> i & 1 == 1 {
            v
        } else {
            F::Not(Box::new(v))
        };
        f = F::And(Box::new(f), Box::new(lit));
    }
    f
}

/// The first header bits of the 2 fields that the formulas use: the
/// destination address near the top of the order and the encapsulation
/// near the end.
const FIELDS: [u32; 2] = [25, BITS - 64];

/// The levels of the 2 fields: 32 bits each, with their 4 levels.
fn pool() -> Vec<u32> {
    FIELDS
        .iter()
        .flat_map(|&start| start * 4..(start + 32) * 4)
        .collect()
}

fn leaf() -> BoxedStrategy<F> {
    prop_oneof![
        1 => prop::sample::select(pool()).prop_map(F::Var),
        4 => (prop::sample::select(FIELDS.to_vec()), 1u32..=32, any::<u32>(), 0u32..4)
            .prop_map(|(s, l, v, b)| prefix(s, l, v, b)),
    ]
    .boxed()
}

struct Oxi {
    vars: Vec<BDDFunction>,
    t: BDDFunction,
}

impl Oxi {
    fn new() -> Oxi {
        let mref = oxidd::bdd::new_manager(1 << 20, 1 << 18, 1);
        let vars: Vec<BDDFunction> = mref
            .with_manager_exclusive(|m| {
                AllocResult::from_iter(m.add_vars(LEVELS).map(|i| BDDFunction::var(m, i)))
            })
            .unwrap();
        let t = vars[0].or(&vars[0].not().unwrap()).unwrap();
        Oxi { vars, t }
    }

    fn cube(&self, ls: &[u32]) -> BDDFunction {
        ls.iter().fold(self.t.clone(), |acc, &l| {
            acc.and(&self.vars[l as usize]).unwrap()
        })
    }

    fn build(&self, f: &F) -> BDDFunction {
        match f {
            F::Const(true) => self.t.clone(),
            F::Const(false) => self.t.not().unwrap(),
            F::Var(l) => self.vars[*l as usize].clone(),
            F::Not(a) => self.build(a).not().unwrap(),
            F::And(a, b) => self.build(a).and(&self.build(b)).unwrap(),
            F::Or(a, b) => self.build(a).or(&self.build(b)).unwrap(),
            F::Xor(a, b) => self.build(a).xor(&self.build(b)).unwrap(),
            F::Diff(a, b) => self.build(a).and(&self.build(b).not().unwrap()).unwrap(),
            F::Ite(c, a, b) => self.build(c).ite(&self.build(a), &self.build(b)).unwrap(),
            F::Exists(a, ls) => self.build(a).exists(&self.cube(ls)).unwrap(),
            F::AndExists(a, b, ls) => self
                .build(a)
                .and(&self.build(b))
                .unwrap()
                .exists(&self.cube(ls))
                .unwrap(),
            F::Rename(a, swaps) => {
                let mut vars = Vec::new();
                let mut repl = Vec::new();
                for &(x, y) in swaps {
                    vars.extend([x, y]);
                    repl.extend([self.vars[y as usize].clone(), self.vars[x as usize].clone()]);
                }
                let subst = oxidd::Subst::new(vars, repl);
                self.build(a).substitute(&subst).unwrap()
            }
        }
    }

    /// The OxiDD function of an edge of the arena.
    fn translate(&self, dd: &Dd, e: Edge, memo: &mut HashMap<Edge, BDDFunction>) -> BDDFunction {
        if e == Edge::TRUE {
            return self.t.clone();
        }
        if e == Edge::FALSE {
            return self.t.not().unwrap();
        }
        if let Some(r) = memo.get(&e) {
            return r.clone();
        }
        let Some((l, lo, hi)) = dd.branch(e).unwrap() else {
            unreachable!("a node that is not constant has a level")
        };
        let lo = self.translate(dd, lo, memo);
        let hi = self.translate(dd, hi, memo);
        let r = self.vars[l as usize].ite(&hi, &lo).unwrap();
        memo.insert(e, r.clone());
        r
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_engine_and_oxidd_give_the_same_sets(f in formula_with(leaf(), pool(), 5)) {
        let oxi = Oxi::new();
        let mut dd = Dd::new(LEVELS);
        let e = build(&mut dd, &f).unwrap();
        let got = oxi.translate(&dd, e, &mut HashMap::new());
        let want = oxi.build(&f);
        prop_assert!(got == want, "the engine and OxiDD differ for {:?}", f);
        dd.validate().unwrap();
    }
}
