//! A plain BDD with no complement edges, for the shadow check. Each public
//! operation of [`Dd`] also runs here, and the 2 results must be the same
//! set.

use crate::dd::{Dd, ShadowOp};
use crate::edge::Edge;
use crate::error::DdError;
use crate::hash::Map;

const FALSE: u32 = 0;
const TRUE: u32 = 1;

/// A plain BDD: node 0 is false, node 1 is true.
#[derive(Default)]
pub(crate) struct Shadow {
    nodes: Vec<(u32, u32, u32)>,
    unique: Map<(u32, u32, u32), u32>,
    /// The plain node of each regular edge of the arena.
    translated: Map<u32, u32>,
}

impl Shadow {
    fn init(&mut self) {
        if self.nodes.is_empty() {
            self.nodes.push((u32::MAX, FALSE, FALSE));
            self.nodes.push((u32::MAX, TRUE, TRUE));
        }
    }

    fn level(&self, n: u32) -> u32 {
        self.nodes[n as usize].0
    }

    fn mk(&mut self, level: u32, lo: u32, hi: u32) -> u32 {
        if lo == hi {
            return lo;
        }
        let k = (level, lo, hi);
        if let Some(&i) = self.unique.get(&k) {
            return i;
        }
        let i = self.nodes.len() as u32;
        self.nodes.push(k);
        self.unique.insert(k, i);
        i
    }

    fn cof(&self, n: u32, level: u32) -> (u32, u32) {
        let (l, lo, hi) = self.nodes[n as usize];
        if l == level { (lo, hi) } else { (n, n) }
    }

    fn apply(
        &mut self,
        a: u32,
        b: u32,
        f: fn(bool, bool) -> bool,
        memo: &mut Map<(u32, u32), u32>,
    ) -> u32 {
        if a <= TRUE && b <= TRUE {
            return u32::from(f(a == TRUE, b == TRUE));
        }
        if let Some(&r) = memo.get(&(a, b)) {
            return r;
        }
        let top = self.level(a).min(self.level(b));
        let (a0, a1) = self.cof(a, top);
        let (b0, b1) = self.cof(b, top);
        let lo = self.apply(a0, b0, f, memo);
        let hi = self.apply(a1, b1, f, memo);
        let r = self.mk(top, lo, hi);
        memo.insert((a, b), r);
        r
    }

    fn bin(&mut self, a: u32, b: u32, f: fn(bool, bool) -> bool) -> u32 {
        self.apply(a, b, f, &mut Map::default())
    }

    fn not(&mut self, a: u32) -> u32 {
        self.bin(a, TRUE, |x, _| !x)
    }

    fn exists(&mut self, f: u32, levels: &[u32], memo: &mut Map<u32, u32>) -> u32 {
        if f <= TRUE {
            return f;
        }
        if let Some(&r) = memo.get(&f) {
            return r;
        }
        let (l, lo, hi) = self.nodes[f as usize];
        let r0 = self.exists(lo, levels, memo);
        let r1 = self.exists(hi, levels, memo);
        let r = if levels.contains(&l) {
            self.bin(r0, r1, |x, y| x || y)
        } else {
            self.mk(l, r0, r1)
        };
        memo.insert(f, r);
        r
    }

    fn rename(&mut self, f: u32, map: &[u32], memo: &mut Map<u32, u32>) -> u32 {
        if f <= TRUE {
            return f;
        }
        if let Some(&r) = memo.get(&f) {
            return r;
        }
        let (l, lo, hi) = self.nodes[f as usize];
        let r0 = self.rename(lo, map, memo);
        let r1 = self.rename(hi, map, memo);
        let v = self.mk(map[l as usize], FALSE, TRUE);
        let a = self.bin(v, r1, |x, y| x && y);
        let nv = self.not(v);
        let b = self.bin(nv, r0, |x, y| x && y);
        let r = self.bin(a, b, |x, y| x || y);
        memo.insert(f, r);
        r
    }

    /// The plain node of an arena edge.
    fn translate(dd: &mut Dd, e: Edge) -> u32 {
        let r = Shadow::translate_regular(dd, e.regular());
        if e.is_complement() {
            dd.shadow_mut().not(r)
        } else {
            r
        }
    }

    fn translate_regular(dd: &mut Dd, e: Edge) -> u32 {
        dd.shadow_mut().init();
        if e == Edge::TRUE {
            return TRUE;
        }
        if let Some(&r) = dd.shadow_mut().translated.get(&e.raw()) {
            return r;
        }
        let level = dd.top_level(e).unwrap_or(u32::MAX);
        let (lo, hi) = dd.cofactors(e, level);
        let lo = Shadow::translate(dd, lo);
        let hi = Shadow::translate(dd, hi);
        let s = dd.shadow_mut();
        let r = s.mk(level, lo, hi);
        s.translated.insert(e.raw(), r);
        r
    }

    /// The levels of a cube.
    fn cube_levels(dd: &Dd, mut c: Edge) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(l) = dd.top_level(c) {
            out.push(l);
            c = dd.cofactors(c, l).1;
        }
        out
    }

    /// Runs `op` in the plain BDD and compares the result with `r`.
    pub(crate) fn check(dd: &mut Dd, op: ShadowOp, r: Edge) -> Result<(), DdError> {
        let t = |dd: &mut Dd, e| Shadow::translate(dd, e);
        let want = match &op {
            ShadowOp::Var(l) => {
                dd.shadow_mut().init();
                dd.shadow_mut().mk(*l, FALSE, TRUE)
            }
            ShadowOp::Cube(ls) => {
                dd.shadow_mut().init();
                let mut acc = TRUE;
                for &l in ls.iter().rev() {
                    acc = dd.shadow_mut().mk(l, FALSE, acc);
                }
                acc
            }
            ShadowOp::And(a, b)
            | ShadowOp::Or(a, b)
            | ShadowOp::Xor(a, b)
            | ShadowOp::Diff(a, b) => {
                let (x, y) = (t(dd, *a), t(dd, *b));
                let f: fn(bool, bool) -> bool = match op {
                    ShadowOp::And(..) => |x, y| x && y,
                    ShadowOp::Or(..) => |x, y| x || y,
                    ShadowOp::Xor(..) => |x, y| x != y,
                    _ => |x, y| x && !y,
                };
                dd.shadow_mut().bin(x, y, f)
            }
            ShadowOp::Ite(f, g, h) => {
                let (f, g, h) = (t(dd, *f), t(dd, *g), t(dd, *h));
                let s = dd.shadow_mut();
                let a = s.bin(f, g, |x, y| x && y);
                let b = s.bin(f, h, |x, y| !x && y);
                s.bin(a, b, |x, y| x || y)
            }
            ShadowOp::Exists(f, c) => {
                let ls = Shadow::cube_levels(dd, *c);
                let f = t(dd, *f);
                dd.shadow_mut().exists(f, &ls, &mut Map::default())
            }
            ShadowOp::AndExists(f, g, c) => {
                let ls = Shadow::cube_levels(dd, *c);
                let (f, g) = (t(dd, *f), t(dd, *g));
                let s = dd.shadow_mut();
                let a = s.bin(f, g, |x, y| x && y);
                s.exists(a, &ls, &mut Map::default())
            }
            ShadowOp::Literals(ls) => {
                dd.shadow_mut().init();
                let s = dd.shadow_mut();
                let mut acc = TRUE;
                if ls.windows(2).any(|w| w[0].0 == w[1].0) {
                    acc = FALSE;
                } else {
                    for &(l, v) in ls.iter().rev() {
                        acc = if v {
                            s.mk(l, FALSE, acc)
                        } else {
                            s.mk(l, acc, FALSE)
                        };
                    }
                }
                acc
            }
            ShadowOp::Import => return Ok(()),
            ShadowOp::Rename(f, m) => {
                let map = dd.map_levels(*m).to_vec();
                let f = t(dd, *f);
                dd.shadow_mut().rename(f, &map, &mut Map::default())
            }
        };
        let got = t(dd, r);
        if got == want {
            Ok(())
        } else {
            Err(DdError::InvariantBroken(format!(
                "the shadow BDD gives a different set for {op:?}"
            )))
        }
    }
}

impl Dd {
    pub(crate) fn shadow_mut(&mut self) -> &mut Shadow {
        &mut self.shadow
    }
}
