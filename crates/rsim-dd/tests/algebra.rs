//! The set algebra, random operation sequences with the validator, the
//! operation caches, and the arenas.

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use proptest::prelude::*;
use rsim_dd::{Dd, DdError, Edge};

const N: u32 = 24;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn set_algebra_holds(fa in formula(N, 5), fb in formula(N, 5), s in swaps(N)) {
        let mut dd = Dd::new(N);
        let a = build(&mut dd, &fa).unwrap();
        let b = build(&mut dd, &fb).unwrap();
        prop_assert_eq!(a.not().not(), a);
        prop_assert_eq!(dd.and(a, a.not()).unwrap(), Edge::FALSE);
        prop_assert_eq!(dd.or(a, a.not()).unwrap(), Edge::TRUE);
        let or = dd.or(a, b).unwrap();
        let and_not = dd.and(a.not(), b.not()).unwrap();
        prop_assert_eq!(or.not(), and_not);
        let and = dd.and(a, b).unwrap();
        let or_not = dd.or(a.not(), b.not()).unwrap();
        prop_assert_eq!(and.not(), or_not);
        prop_assert_eq!(dd.diff(a, b).unwrap(), dd.and(a, b.not()).unwrap());
        prop_assert_eq!(dd.and(a, b).unwrap(), dd.and(b, a).unwrap());
        prop_assert_eq!(dd.xor(a, b).unwrap(), dd.xor(b.not(), a.not()).unwrap());
        let pairs: Vec<(u32, u32)> = s.iter().flat_map(|&(x, y)| [(x, y), (y, x)]).collect();
        let m = dd.map(&pairs).unwrap();
        let r = dd.rename(a, m).unwrap();
        prop_assert_eq!(dd.rename(r, m).unwrap(), a);
        dd.validate().unwrap();
    }
}

/// One step of an operation sequence on a pool of functions.
#[derive(Clone, Debug)]
enum Step {
    Var(u32),
    Not(usize),
    And(usize, usize),
    Or(usize, usize),
    Xor(usize, usize),
    Diff(usize, usize),
    Ite(usize, usize, usize),
    Exists(usize, Vec<u32>),
    AndExists(usize, usize, Vec<u32>),
    Rename(usize, Vec<(u32, u32)>),
}

fn step() -> impl Strategy<Value = Step> {
    let i = || 0usize..64;
    prop_oneof![
        3 => (0..N).prop_map(Step::Var),
        1 => i().prop_map(Step::Not),
        3 => (i(), i()).prop_map(|(a, b)| Step::And(a, b)),
        3 => (i(), i()).prop_map(|(a, b)| Step::Or(a, b)),
        2 => (i(), i()).prop_map(|(a, b)| Step::Xor(a, b)),
        2 => (i(), i()).prop_map(|(a, b)| Step::Diff(a, b)),
        1 => (i(), i(), i()).prop_map(|(a, b, c)| Step::Ite(a, b, c)),
        1 => (i(), levels(N, 4)).prop_map(|(a, l)| Step::Exists(a, l)),
        1 => (i(), i(), levels(N, 4)).prop_map(|(a, b, l)| Step::AndExists(a, b, l)),
        1 => (i(), swaps(N)).prop_map(|(a, s)| Step::Rename(a, s)),
    ]
}

/// Runs the steps. Each step adds its result to the pool. An index picks a
/// pool entry modulo the pool size.
fn run(dd: &mut Dd, pool: &mut Vec<Edge>, steps: &[Step]) -> Result<(), DdError> {
    for s in steps {
        let p = |i: &usize| pool[i % pool.len()];
        let r = match s {
            Step::Var(l) => dd.var(*l)?,
            Step::Not(a) => p(a).not(),
            Step::And(a, b) => dd.and(p(a), p(b))?,
            Step::Or(a, b) => dd.or(p(a), p(b))?,
            Step::Xor(a, b) => dd.xor(p(a), p(b))?,
            Step::Diff(a, b) => dd.diff(p(a), p(b))?,
            Step::Ite(a, b, c) => dd.ite(p(a), p(b), p(c))?,
            Step::Exists(a, l) => {
                let c = dd.cube(l)?;
                dd.exists(p(a), c)?
            }
            Step::AndExists(a, b, l) => {
                let c = dd.cube(l)?;
                dd.and_exists(p(a), p(b), c)?
            }
            Step::Rename(a, s) => {
                let pairs: Vec<(u32, u32)> =
                    s.iter().flat_map(|&(x, y)| [(x, y), (y, x)]).collect();
                let m = dd.map(&pairs)?;
                dd.rename(p(a), m)?
            }
        };
        pool.push(r);
        dd.validate()?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn operation_sequences_keep_the_arena_valid(steps in prop::collection::vec(step(), 1..60)) {
        let mut dd = Dd::new(N);
        let mut pool = vec![Edge::TRUE, Edge::FALSE];
        run(&mut dd, &mut pool, &steps).unwrap();
    }

    #[test]
    fn the_caches_do_not_change_a_result(steps in prop::collection::vec(step(), 1..60)) {
        let mut on = Dd::new(N);
        let mut off = Dd::new(N);
        off.set_caches(false);
        let mut p_on = vec![Edge::TRUE, Edge::FALSE];
        let mut p_off = p_on.clone();
        run(&mut on, &mut p_on, &steps).unwrap();
        run(&mut off, &mut p_off, &steps).unwrap();
        prop_assert_eq!(&p_on, &p_off);
        prop_assert_eq!(on.local_nodes(), off.local_nodes());
    }

    #[test]
    fn a_scratch_arena_on_a_frozen_arena_stays_valid(
        twin in prop::collection::vec(step(), 1..30),
        query in prop::collection::vec(step(), 1..40),
    ) {
        let mut root = Dd::new(N);
        let mut pool = vec![Edge::TRUE, Edge::FALSE];
        run(&mut root, &mut pool, &twin).unwrap();
        let frozen = root.freeze().unwrap();
        frozen.validate().unwrap();
        let mut scratch = Dd::scratch(Arc::clone(&frozen), None);
        let mut q = pool.clone();
        run(&mut scratch, &mut q, &query).unwrap();
        // The functions of the twin need no new node in the scratch arena.
        let mut again = Dd::scratch(Arc::clone(&frozen), None);
        let mut p2 = vec![Edge::TRUE, Edge::FALSE];
        run(&mut again, &mut p2, &twin).unwrap();
        prop_assert_eq!(&p2, &pool);
        prop_assert_eq!(again.local_nodes(), 0);
    }
}

fn sample(dd: &mut Dd) -> Edge {
    let mut acc = Edge::TRUE;
    for l in (0..N).step_by(3) {
        let v = dd.var(l).unwrap();
        let w = dd.var(l + 1).unwrap();
        let x = dd.xor(v, w).unwrap();
        acc = dd.and(acc, x).unwrap();
    }
    acc
}

#[test]
fn a_scratch_arena_stops_at_its_node_budget() {
    let frozen = Dd::new(N).freeze().unwrap();
    let mut dd = Dd::scratch(frozen, Some(5));
    let mut err = None;
    for l in 0..N {
        if let Err(e) = dd.var(l) {
            err = Some(e);
            break;
        }
    }
    assert_eq!(err, Some(DdError::NodeBudget { budget: 5 }));
    assert_eq!(dd.local_nodes(), 5);
    dd.validate().unwrap();
    // The arena still works for functions that need no new node.
    let v = dd.var(0).unwrap();
    assert_eq!(dd.and(v, v.not()).unwrap(), Edge::FALSE);
}

#[test]
fn a_read_only_arena_creates_no_node() {
    let mut root = Dd::new(N);
    let v = root.var(0).unwrap();
    let frozen = root.freeze().unwrap();
    let mut ro = Dd::read_only(frozen);
    assert_eq!(ro.var(0).unwrap(), v);
    assert_eq!(ro.var(1), Err(DdError::ArenaFrozen));
}

#[test]
fn errors_name_their_kind() {
    let mut dd = Dd::new(4);
    assert_eq!(
        dd.var(4),
        Err(DdError::LevelOutOfRange {
            level: 4,
            levels: 4
        })
    );
    assert!(matches!(
        dd.map(&[(0, 1)]),
        Err(DdError::InvariantBroken(_))
    ));
    let mut other = Dd::new(4);
    let mut far = Edge::TRUE;
    for l in 0..4 {
        let v = other.var(l).unwrap();
        far = other.and(far, v).unwrap();
    }
    assert!(matches!(dd.and(far, far), Err(DdError::InvariantBroken(_))));
    assert!(dd.eval(far, |_| true).is_err());
    assert!(dd.branch(far).is_err());
    assert!(dd.top(far).is_err());
    assert!(dd.pick_one(far).is_err());
    assert!(dd.size(far).is_err());
    assert!(dd.sat_count(far).is_err());
    let v = dd.var(0).unwrap();
    assert!(matches!(
        dd.exists(v, v.not()),
        Err(DdError::InvariantBroken(_))
    ));
}

#[test]
fn threads_share_a_frozen_arena_and_get_the_same_results() {
    let mut root = Dd::new(N);
    let base = sample(&mut root);
    let frozen = root.freeze().unwrap();
    let results: Vec<(Edge, usize)> = thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let frozen = Arc::clone(&frozen);
                s.spawn(move || {
                    let mut dd = Dd::scratch(frozen, Some(100_000));
                    let extra = sample(&mut dd);
                    assert_eq!(extra, base);
                    let v = dd.var(N - 1).unwrap();
                    let r = dd.or(base, v).unwrap();
                    (r, dd.local_nodes())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(results.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn sat_count_and_pick_one_on_a_known_set() {
    let mut dd = Dd::new(8);
    // Levels 0 to 3 are 1010: 16 assignments of the other 4 levels.
    let mut f = Edge::TRUE;
    for (l, v) in [(0, true), (1, false), (2, true), (3, false)] {
        let x = dd.var(l).unwrap();
        f = dd.and(f, if v { x } else { x.not() }).unwrap();
    }
    assert_eq!(dd.sat_count(f).unwrap(), 16);
    assert_eq!(
        dd.pick_one(f).unwrap().unwrap(),
        vec![(0, true), (1, false), (2, true), (3, false)]
    );
    assert_eq!(dd.pick_one(Edge::FALSE), Ok(None));
    assert_eq!(dd.sat_count(Edge::TRUE).unwrap(), 256);
    assert_eq!(dd.size(f), Ok(5));
    assert!(Dd::new(128).sat_count(Edge::TRUE).is_err());
}

/// A packet is a chain of 1 literal on each level. The operations recurse
/// once for each level, on a thread with the default stack.
#[test]
fn a_chain_on_all_3052_levels_runs_on_a_default_thread() {
    const LEVELS: u32 = 3052;
    let r = thread::spawn(|| {
        let mut dd = Dd::new(LEVELS);
        // The plain BDD of the shadow check recurses, so it is off here.
        dd.set_shadow(false);
        let mut a = Edge::TRUE;
        let mut b = Edge::TRUE;
        for l in (0..LEVELS).rev() {
            let v = dd.var(l).unwrap();
            a = dd.and(if l % 3 == 0 { v.not() } else { v }, a).unwrap();
            b = dd.and(if l % 5 == 0 { v.not() } else { v }, b).unwrap();
        }
        let x = dd.xor(a, b).unwrap();
        let o = dd.or(a, b).unwrap();
        let all: Vec<u32> = (0..LEVELS).step_by(2).collect();
        let cube = dd.cube(&all).unwrap();
        let e = dd.exists(o, cube).unwrap();
        let ae = dd.and_exists(a, o, cube).unwrap();
        // Reverse the order of the levels: the rename is not monotone.
        let pairs: Vec<(u32, u32)> = (0..LEVELS).map(|l| (l, LEVELS - 1 - l)).collect();
        let m = dd.map(&pairs).unwrap();
        let r = dd.rename(a, m).unwrap();
        let back = dd.rename(r, m).unwrap();
        assert_eq!(back, a);
        dd.validate().unwrap();
        (x, e, ae, dd.size(a).unwrap())
    })
    .join()
    .unwrap();
    // 1 node for each level and the terminal.
    assert_eq!(r.3, LEVELS as usize + 1);
}

/// The truth table over the levels below `M`.
const M: u32 = 12;

fn table(dd: &Dd, f: Edge) -> Vec<bool> {
    (0..1usize << M)
        .map(|i| dd.eval(f, |l| i >> l & 1 == 1).unwrap())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn an_import_gives_the_same_function(
        twin in prop::collection::vec(step(), 1..20),
        f in formula(M, 5),
    ) {
        let mut root = Dd::new(N);
        let mut pool = vec![Edge::TRUE, Edge::FALSE];
        run(&mut root, &mut pool, &twin).unwrap();
        let frozen = root.freeze().unwrap();
        let mut a = Dd::scratch(Arc::clone(&frozen), None);
        let e = build(&mut a, &f).unwrap();
        let want = table(&a, e);

        // A scratch arena on the same frozen arena.
        let mut b = Dd::scratch(Arc::clone(&frozen), None);
        let eb = b.import(&a, e).unwrap();
        prop_assert_eq!(table(&b, eb), want.clone());
        b.validate().unwrap();
        // The same function built in the target arena has the same edge.
        let again = build(&mut b, &f).unwrap();
        prop_assert_eq!(again, eb);

        // A root arena with no frozen base.
        let mut c = Dd::new(N);
        let ec = c.import(&a, e).unwrap();
        prop_assert_eq!(table(&c, ec), want);
        c.validate().unwrap();
    }

    #[test]
    fn literals_give_their_conjunction(lits in prop::collection::vec((0..M, any::<bool>()), 0..8)) {
        let mut dd = Dd::new(N);
        let e = dd.literals(&lits).unwrap();
        let got = table(&dd, e);
        for (i, g) in got.into_iter().enumerate() {
            let want = lits.iter().all(|&(l, v)| (i >> l & 1 == 1) == v);
            prop_assert_eq!(g, want);
        }
    }
}

#[test]
fn an_import_needs_the_same_number_of_levels() {
    let mut a = Dd::new(4);
    let e = a.var(2).unwrap();
    let mut b = Dd::new(5);
    assert!(matches!(b.import(&a, e), Err(DdError::InvariantBroken(_))));
}
