//! The arenas, the node constructor and the operations.

use std::sync::Arc;

use crate::edge::Edge;
use crate::error::DdError;
use crate::hash::Map;

/// The level of the terminal node: below each variable level.
pub(crate) const TERMINAL_LEVEL: u32 = u32::MAX;

/// A stored node. The 1 edge (`hi`) is never complemented, and `lo` is not
/// equal to `hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Node {
    pub level: u32,
    pub lo: Edge,
    pub hi: Edge,
}

const TERMINAL: Node = Node {
    level: TERMINAL_LEVEL,
    lo: Edge::TRUE,
    hi: Edge::TRUE,
};

/// A read-only arena. All threads can share it. A scratch arena reads it
/// and adds its own nodes after it.
#[derive(Debug)]
pub struct Frozen {
    levels: u32,
    nodes: Vec<Node>,
    unique: Map<Node, u32>,
}

impl Frozen {
    pub fn levels(&self) -> u32 {
        self.levels
    }

    /// The number of nodes, with the terminal node.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Checks the node form, the level order and the unique table. No edge
    /// may point out of the arena.
    pub fn validate(&self) -> Result<(), DdError> {
        let total = self.nodes.len() as u32;
        if self.nodes.first() != Some(&TERMINAL) {
            return Err(broken("node 0 is not the terminal node"));
        }
        let level_of = |i: u32| self.nodes[i as usize].level;
        for (i, n) in self.nodes.iter().enumerate().skip(1) {
            check_node(self.levels, i as u32, n, total, level_of)?;
            if self.unique.get(n) != Some(&(i as u32)) {
                return Err(broken(&format!("node {i} is not in the unique table")));
            }
        }
        if self.unique.len() != self.nodes.len() - 1 {
            return Err(broken("the unique table has entries with no node"));
        }
        Ok(())
    }
}

fn broken(d: &str) -> DdError {
    DdError::InvariantBroken(d.to_string())
}

/// Checks one stored node: its level, its form, and that each child is in
/// the arena and has a higher level.
fn check_node(
    levels: u32,
    index: u32,
    n: &Node,
    total: u32,
    level_of: impl Fn(u32) -> u32,
) -> Result<(), DdError> {
    if n.level >= levels {
        return Err(broken(&format!("node {index} has level {}", n.level)));
    }
    if n.hi.is_complement() {
        return Err(broken(&format!("node {index} has a complemented 1 edge")));
    }
    if n.lo == n.hi {
        return Err(broken(&format!("node {index} has 2 equal edges")));
    }
    for c in [n.lo, n.hi] {
        if c.index() >= total {
            return Err(broken(&format!(
                "node {index} has an edge to node {}, which is not in the arena",
                c.index()
            )));
        }
        if level_of(c.index()) <= n.level {
            return Err(broken(&format!(
                "node {index} has a child that is not at a higher level"
            )));
        }
    }
    Ok(())
}

/// The operations that have a cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    And,
    Xor,
    Exists,
    AndExists,
    Rename,
    Insert,
}

type Key = (Op, u32, u32, u32);

/// The cache key of an operation, and true if the cached result must be
/// complemented. Commutative operands are in a fixed order, and the
/// complement flags are normalised where the operation allows it.
fn key(op: Op, a: Edge, b: Edge, c: u32) -> (Key, bool) {
    match op {
        Op::And | Op::AndExists => {
            let (x, y) = if a.raw() <= b.raw() { (a, b) } else { (b, a) };
            ((op, x.raw(), y.raw(), c), false)
        }
        Op::Xor => {
            let neg = a.is_complement() ^ b.is_complement();
            let (x, y) = (a.regular(), b.regular());
            let (x, y) = if x.raw() <= y.raw() { (x, y) } else { (y, x) };
            ((op, x.raw(), y.raw(), 0), neg)
        }
        Op::Exists => ((op, a.raw(), b.raw(), 0), false),
        Op::Rename => ((op, a.regular().raw(), c, 0), a.is_complement()),
        Op::Insert => {
            let neg = b.is_complement();
            let (lo, hi) = (a.xor_complement(neg), b.xor_complement(neg));
            ((op, lo.raw(), hi.raw(), c), neg)
        }
    }
}

/// The distance in levels up to which [`Dd::rename`] moves a level above the
/// image of a level above it without a cut.
const NEAR: u32 = 16;
/// The most cuts of one rename by cuts.
const MAX_CUTS: usize = 64;
/// The most leaves of the upper part of one cut.
const MAX_LEAVES: usize = 64;

/// The identifier of a level map for [`Dd::rename`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MapId(u32);

/// An arena with the operations on its functions.
///
/// A root arena holds its own nodes and can freeze into a [`Frozen`]
/// arena. A scratch arena reads a frozen arena and adds its nodes after
/// it, up to its node budget. A read-only arena reads a frozen arena and
/// creates no node.
pub struct Dd {
    levels: u32,
    base: Option<Arc<Frozen>>,
    offset: u32,
    nodes: Vec<Node>,
    unique: Map<Node, u32>,
    cache: Map<Key, Edge>,
    caches: bool,
    budget: Option<usize>,
    read_only: bool,
    shadow_on: bool,
    maps: Vec<Vec<u32>>,
    /// For each level map, true if it moves a level more than [`NEAR`]
    /// levels above the image of a level above it.
    far: Vec<bool>,
    /// The local nodes that the validator has checked.
    checked: usize,
    /// The task stack and the value stack of the evaluator, kept for reuse.
    tasks: Vec<Task>,
    vals: Vec<Edge>,
    #[cfg(feature = "dd-shadow")]
    pub(crate) shadow: crate::plain::Shadow,
}

impl Dd {
    fn with(levels: u32, base: Option<Arc<Frozen>>, budget: Option<usize>, ro: bool) -> Dd {
        let offset = base.as_ref().map_or(0, |b| b.nodes.len() as u32);
        let nodes = if base.is_some() {
            Vec::new()
        } else {
            vec![TERMINAL]
        };
        let checked = nodes.len();
        Dd {
            levels,
            base,
            offset,
            nodes,
            unique: Map::default(),
            cache: Map::default(),
            caches: true,
            budget,
            read_only: ro,
            shadow_on: true,
            maps: Vec::new(),
            far: Vec::new(),
            checked,
            tasks: Vec::new(),
            vals: Vec::new(),
            #[cfg(feature = "dd-shadow")]
            shadow: crate::plain::Shadow::default(),
        }
    }

    /// A root arena with `levels` variable levels.
    pub fn new(levels: u32) -> Dd {
        Dd::with(levels, None, None, false)
    }

    /// A scratch arena on a frozen arena. With a budget, the scratch arena
    /// holds at most that number of its own nodes.
    pub fn scratch(frozen: Arc<Frozen>, budget: Option<usize>) -> Dd {
        Dd::with(frozen.levels, Some(frozen), budget, false)
    }

    /// A read-only arena on a frozen arena. An operation that needs a new
    /// node gives [`DdError::ArenaFrozen`].
    pub fn read_only(frozen: Arc<Frozen>) -> Dd {
        Dd::with(frozen.levels, Some(frozen), None, true)
    }

    /// Validates a root arena and makes it read-only. The edges of the root
    /// arena stay valid in the frozen arena.
    pub fn freeze(self) -> Result<Arc<Frozen>, DdError> {
        if self.base.is_some() {
            return Err(broken("only a root arena can freeze"));
        }
        let f = Frozen {
            levels: self.levels,
            nodes: self.nodes,
            unique: self.unique,
        };
        f.validate()?;
        Ok(Arc::new(f))
    }

    /// With the feature `dd-shadow`, turns the shadow check on or off. It is
    /// on by default. Without the feature, there is no shadow check.
    pub fn set_shadow(&mut self, on: bool) {
        self.shadow_on = on;
    }

    /// Reserves room for `nodes` more nodes and their table entries.
    pub fn reserve(&mut self, nodes: usize) {
        self.reserve_tables(nodes, nodes);
    }

    /// Reserves room for `nodes` more nodes with their entries of the unique
    /// table, and for `cache` more entries of the operation caches.
    pub fn reserve_tables(&mut self, nodes: usize, cache: usize) {
        self.nodes.reserve(nodes);
        self.unique.reserve(nodes);
        self.cache.reserve(cache);
    }

    /// The number of entries of the operation caches.
    pub fn cache_entries(&self) -> usize {
        self.cache.len()
    }

    /// Turns the operation caches on or off.
    pub fn set_caches(&mut self, on: bool) {
        self.caches = on;
        self.cache.clear();
    }

    pub fn levels(&self) -> u32 {
        self.levels
    }

    /// The number of nodes of this arena, without a frozen base.
    pub fn local_nodes(&self) -> usize {
        self.nodes.len()
    }

    fn total(&self) -> u32 {
        self.offset + self.nodes.len() as u32
    }

    pub(crate) fn node(&self, index: u32) -> Node {
        match &self.base {
            Some(b) if index < self.offset => b.nodes[index as usize],
            _ => self.nodes[(index - self.offset) as usize],
        }
    }

    /// The level of the top variable of `e`. A constant has no variable
    /// and gives `None`.
    pub fn top(&self, e: Edge) -> Result<Option<u32>, DdError> {
        self.check_edges(&[e])?;
        Ok(self.top_level(e))
    }

    pub(crate) fn top_level(&self, e: Edge) -> Option<u32> {
        let l = self.level(e);
        (l != TERMINAL_LEVEL).then_some(l)
    }

    /// The top level of `e`, its 0 child and its 1 child, with the complement
    /// flag of `e` applied to the children. A constant gives `None`.
    pub fn branch(&self, e: Edge) -> Result<Option<(u32, Edge, Edge)>, DdError> {
        self.check_edges(&[e])?;
        Ok(self.top_level(e).map(|l| {
            let (lo, hi) = self.cofactors(e, l);
            (l, lo, hi)
        }))
    }

    pub(crate) fn level(&self, e: Edge) -> u32 {
        self.node(e.index()).level
    }

    /// The 0 child and the 1 child of `e` at `level`.
    pub(crate) fn cofactors(&self, e: Edge, level: u32) -> (Edge, Edge) {
        let n = self.node(e.index());
        if n.level == level {
            let c = e.is_complement();
            (n.lo.xor_complement(c), n.hi.xor_complement(c))
        } else {
            (e, e)
        }
    }

    /// The only node constructor. It applies the canonical form and checks
    /// the level order.
    fn mk(&mut self, level: u32, lo: Edge, hi: Edge) -> Result<Edge, DdError> {
        if lo == hi {
            return Ok(lo);
        }
        let c = hi.is_complement();
        let (lo, hi) = (lo.xor_complement(c), hi.xor_complement(c));
        if self.level(lo) <= level || self.level(hi) <= level {
            return Err(broken(&format!(
                "a child of a new node at level {level} is not at a higher level"
            )));
        }
        let n = Node { level, lo, hi };
        if let Some(b) = &self.base
            && let Some(&i) = b.unique.get(&n)
        {
            return Ok(Edge::new(i, c));
        }
        if let Some(&i) = self.unique.get(&n) {
            return Ok(Edge::new(i, c));
        }
        if self.read_only {
            return Err(DdError::ArenaFrozen);
        }
        if let Some(budget) = self.budget
            && self.nodes.len() >= budget
        {
            return Err(DdError::NodeBudget { budget });
        }
        let i = self.total();
        if i > Edge::MAX_INDEX {
            return Err(broken("the arena is full"));
        }
        self.nodes.push(n);
        self.unique.insert(n, i);
        Ok(Edge::new(i, c))
    }

    fn cached(&self, k: &Key, neg: bool) -> Option<Edge> {
        if !self.caches {
            return None;
        }
        self.cache.get(k).map(|r| r.xor_complement(neg))
    }

    fn store(&mut self, k: Key, neg: bool, r: Edge) {
        if self.caches {
            self.cache.insert(k, r.xor_complement(neg));
        }
    }

    fn check_level(&self, level: u32) -> Result<(), DdError> {
        if level < self.levels {
            Ok(())
        } else {
            Err(DdError::LevelOutOfRange {
                level,
                levels: self.levels,
            })
        }
    }

    fn check_edges(&self, es: &[Edge]) -> Result<(), DdError> {
        let total = self.total();
        match es.iter().find(|e| e.index() >= total) {
            Some(e) => Err(broken(&format!("edge {e:?} is not in this arena"))),
            None => Ok(()),
        }
    }

    /// Validates the new nodes in debug builds and with the feature
    /// `dd-check`, and compares the result with the plain BDD with the
    /// feature `dd-shadow`.
    #[allow(unused_variables)]
    fn post(&mut self, op: ShadowOp, r: Edge) -> Result<Edge, DdError> {
        #[cfg(any(debug_assertions, feature = "dd-check"))]
        self.validate_new()?;
        #[cfg(feature = "dd-shadow")]
        if self.shadow_on {
            crate::plain::Shadow::check(self, op, r)?;
        }
        Ok(r)
    }

    /// Checks the nodes that were added since the last check.
    fn validate_new(&mut self) -> Result<(), DdError> {
        let total = self.total();
        for i in self.checked..self.nodes.len() {
            let index = self.offset + i as u32;
            let n = self.nodes[i];
            check_node(self.levels, index, &n, total, |c| self.node(c).level)?;
            if self.unique.get(&n) != Some(&index) {
                return Err(broken(&format!("node {index} is not in the unique table")));
            }
            if let Some(b) = &self.base
                && b.unique.contains_key(&n)
            {
                return Err(broken(&format!(
                    "node {index} is a duplicate of a frozen node"
                )));
            }
        }
        self.checked = self.nodes.len();
        if self.unique.len() + usize::from(self.base.is_none()) != self.nodes.len() {
            return Err(broken("the unique table does not agree with the arena"));
        }
        Ok(())
    }

    /// Checks all nodes of this arena: the node form, the level order, no
    /// duplicate node, the unique table, and no edge out of the arena.
    pub fn validate(&mut self) -> Result<(), DdError> {
        if self.base.is_none() && self.nodes.first() != Some(&TERMINAL) {
            return Err(broken("node 0 is not the terminal node"));
        }
        self.checked = usize::from(self.base.is_none());
        self.validate_new()
    }

    // ------------------------------------------------------------ variables

    /// The function that is true where the variable at `level` is 1.
    pub fn var(&mut self, level: u32) -> Result<Edge, DdError> {
        self.check_level(level)?;
        let r = self.mk(level, Edge::FALSE, Edge::TRUE)?;
        self.post(ShadowOp::Var(level), r)
    }

    /// The conjunction of the variables at `levels`, for [`Dd::exists`] and
    /// [`Dd::and_exists`].
    pub fn cube(&mut self, levels: &[u32]) -> Result<Edge, DdError> {
        let mut ls = levels.to_vec();
        ls.sort_unstable();
        ls.dedup();
        let mut acc = Edge::TRUE;
        for &l in ls.iter().rev() {
            self.check_level(l)?;
            acc = self.mk(l, Edge::FALSE, acc)?;
        }
        self.post(ShadowOp::Cube(ls), acc)
    }

    /// The conjunction of literals. Each pair is a level and the value of
    /// its variable. Two pairs with one level and different values give
    /// false.
    pub fn literals(&mut self, lits: &[(u32, bool)]) -> Result<Edge, DdError> {
        let mut ls = lits.to_vec();
        ls.sort_unstable();
        ls.dedup();
        if ls.windows(2).any(|w| w[0].0 == w[1].0) {
            return self.post(ShadowOp::Literals(ls), Edge::FALSE);
        }
        let mut acc = Edge::TRUE;
        for &(l, v) in ls.iter().rev() {
            self.check_level(l)?;
            acc = if v {
                self.mk(l, Edge::FALSE, acc)?
            } else {
                self.mk(l, acc, Edge::FALSE)?
            };
        }
        self.post(ShadowOp::Literals(ls), acc)
    }

    /// The function of `e` in the arena `from`, made in this arena. The two
    /// arenas must have the same number of levels. A node of a frozen arena
    /// that both arenas read stays as it is.
    pub fn import(&mut self, from: &Dd, e: Edge) -> Result<Edge, DdError> {
        from.check_edges(&[e])?;
        if from.levels != self.levels {
            return Err(broken("the two arenas have different numbers of levels"));
        }
        let shared = match (&self.base, &from.base) {
            (Some(a), Some(b)) if Arc::ptr_eq(a, b) => from.offset,
            _ => 1,
        };
        let mut done: Map<u32, Edge> = Map::default();
        let mut stack = vec![e.index()];
        while let Some(&i) = stack.last() {
            if i < shared || done.contains_key(&i) {
                stack.pop();
                continue;
            }
            let n = from.node(i);
            let pending: Vec<u32> = [n.lo.index(), n.hi.index()]
                .into_iter()
                .filter(|c| *c >= shared && !done.contains_key(c))
                .collect();
            if !pending.is_empty() {
                stack.extend(pending);
                continue;
            }
            stack.pop();
            let get = |c: Edge| -> Edge {
                let r = if c.index() < shared {
                    c.regular()
                } else {
                    done[&c.index()]
                };
                r.xor_complement(c.is_complement())
            };
            let (lo, hi) = (get(n.lo), get(n.hi));
            let r = self.mk(n.level, lo, hi)?;
            done.insert(i, r);
        }
        let r = if e.index() < shared {
            e.regular()
        } else {
            done[&e.index()]
        };
        self.post(ShadowOp::Import, r.xor_complement(e.is_complement()))
    }

    // ------------------------------------------------------------ boolean

    pub fn and(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[a, b])?;
        let r = self.and_rec(a, b)?;
        self.post(ShadowOp::And(a, b), r)
    }

    pub fn or(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[a, b])?;
        let r = self.or_rec(a, b)?;
        self.post(ShadowOp::Or(a, b), r)
    }

    pub fn xor(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[a, b])?;
        let r = self.xor_rec(a, b)?;
        self.post(ShadowOp::Xor(a, b), r)
    }

    /// The set difference `a and not b`.
    pub fn diff(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[a, b])?;
        let r = self.and_rec(a, b.not())?;
        self.post(ShadowOp::Diff(a, b), r)
    }

    /// If `f` then `g` else `h`.
    pub fn ite(&mut self, f: Edge, g: Edge, h: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[f, g, h])?;
        let r = self.ite_rec(f, g, h)?;
        self.post(ShadowOp::Ite(f, g, h), r)
    }

    // ------------------------------------------------------------ quantifiers

    /// The first variable of the cube `c` at or below `level`.
    fn skip_cube(&self, mut c: Edge, level: u32) -> Edge {
        while !c.is_constant() && self.level(c) < level {
            c = self.cofactors(c, self.level(c)).1;
        }
        c
    }

    /// The existential quantification of `f` over the variables of the cube
    /// `cube`.
    pub fn exists(&mut self, f: Edge, cube: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[f, cube])?;
        self.check_cube(cube)?;
        let r = self.exists_rec(f, cube)?;
        self.post(ShadowOp::Exists(f, cube), r)
    }

    /// The existential quantification of `f and g` over the variables of the
    /// cube `cube`, in one pass.
    pub fn and_exists(&mut self, f: Edge, g: Edge, cube: Edge) -> Result<Edge, DdError> {
        self.check_edges(&[f, g, cube])?;
        self.check_cube(cube)?;
        let r = self.and_exists_rec(f, g, cube)?;
        self.post(ShadowOp::AndExists(f, g, cube), r)
    }

    /// Checks that `c` is a conjunction of positive variables.
    fn check_cube(&self, mut c: Edge) -> Result<(), DdError> {
        while !c.is_constant() {
            let n = self.node(c.index());
            if c.is_complement() || n.lo != Edge::FALSE {
                return Err(broken("the cube is not a conjunction of variables"));
            }
            c = n.hi;
        }
        if c == Edge::TRUE {
            Ok(())
        } else {
            Err(broken("the cube is false"))
        }
    }

    // ------------------------------------------------------------ rename

    /// Registers a level map. Each pair moves the variable of the first level
    /// to the second level. Levels that no pair names stay. The map must be
    /// injective.
    pub fn map(&mut self, pairs: &[(u32, u32)]) -> Result<MapId, DdError> {
        let mut m: Vec<u32> = (0..self.levels).collect();
        for &(from, to) in pairs {
            self.check_level(from)?;
            self.check_level(to)?;
            m[from as usize] = to;
        }
        let mut sorted = m.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != m.len() {
            return Err(broken("the level map is not injective"));
        }
        let mut high = 0;
        let far = m.iter().any(|&t| {
            high = high.max(t);
            t + NEAR < high
        });
        self.far.push(far);
        self.maps.push(m);
        Ok(MapId(self.maps.len() as u32 - 1))
    }

    #[cfg(feature = "dd-shadow")]
    pub(crate) fn map_levels(&self, map: MapId) -> &[u32] {
        &self.maps[map.0 as usize]
    }

    /// The function with each variable moved by the level map `map`.
    ///
    /// A map that moves a level far above the image of a level above it
    /// renames by cuts.
    pub fn rename(&mut self, f: Edge, map: MapId) -> Result<Edge, DdError> {
        self.check_edges(&[f])?;
        if map.0 as usize >= self.maps.len() {
            return Err(broken("the level map is not registered"));
        }
        let r = if self.far[map.0 as usize] {
            self.rename_cut(f, map)?
        } else {
            self.rename_rec(f, map)?
        };
        self.post(ShadowOp::Rename(f, map), r)
    }

    /// The rename of `f` by cuts. The cuts are the levels of the support of
    /// `f` whose image lies more than [`NEAR`] levels above the highest
    /// image of the levels above them since the last cut. With no cut, or
    /// with more than [`MAX_CUTS`] cuts, it is the rename of
    /// [`Dd::rename_rec`].
    fn rename_cut(&mut self, f: Edge, map: MapId) -> Result<Edge, DdError> {
        if f.is_constant() {
            return Ok(f);
        }
        let support = self.support(f);
        let m = &self.maps[map.0 as usize];
        let mut cuts = Vec::new();
        let mut high = None;
        for l in support {
            let t = m[l as usize];
            match high {
                Some(h) if t + NEAR < h => {
                    cuts.push(l);
                    high = Some(t);
                }
                Some(h) => high = Some(t.max(h)),
                None => high = Some(t),
            }
        }
        if cuts.is_empty() || cuts.len() > MAX_CUTS {
            return self.rename_rec(f, map);
        }
        let mut memo = Map::default();
        self.cut_rec(f, map, &cuts, &mut memo)
    }

    /// The rename of `f` with the cuts `cuts`. The part of `f` above the
    /// first cut below its top level reaches the edges at or below the cut,
    /// its leaves. `f` is the disjunction over the leaves of the indicator
    /// of the paths of the upper part to the leaf and the leaf, and the
    /// rename of `f` is the disjunction of their renames. The upper part
    /// lies between 2 cuts, so the rename of an indicator is near the
    /// order. The recursion goes one cut deeper for each leaf. With more
    /// than [`MAX_LEAVES`] leaves, it is the rename of [`Dd::rename_rec`].
    fn cut_rec(
        &mut self,
        f: Edge,
        map: MapId,
        cuts: &[u32],
        memo: &mut Map<Edge, Edge>,
    ) -> Result<Edge, DdError> {
        if f.is_constant() {
            return Ok(f);
        }
        let neg = f.is_complement();
        let f = f.regular();
        if let Some(&r) = memo.get(&f) {
            return Ok(r.xor_complement(neg));
        }
        let (key, _) = key(Op::Rename, f, Edge::TRUE, map.0);
        if let Some(r) = self.cached(&key, false) {
            memo.insert(f, r);
            return Ok(r.xor_complement(neg));
        }
        let top = self.level(f);
        let i = cuts.partition_point(|&c| c <= top);
        let r = match cuts.get(i) {
            None => self.rename_rec(f, map)?,
            Some(&cut) => {
                let leaves = self.leaves(f, cut);
                if leaves.len() > MAX_LEAVES {
                    self.rename_rec(f, map)?
                } else {
                    let mut acc = Edge::FALSE;
                    for g in leaves {
                        if g == Edge::FALSE {
                            continue;
                        }
                        let c = self.indicator(f, cut, g)?;
                        let c = self.rename_rec(c, map)?;
                        let g = self.cut_rec(g, map, &cuts[i + 1..], memo)?;
                        let part = self.and_rec(c, g)?;
                        acc = self.or_rec(acc, part)?;
                    }
                    acc
                }
            }
        };
        self.store(key, false, r);
        memo.insert(f, r);
        Ok(r.xor_complement(neg))
    }

    /// The levels of the support of `f`, in order.
    fn support(&self, f: Edge) -> Vec<u32> {
        let mut seen: Map<u32, ()> = Map::default();
        let mut levels = vec![false; self.levels as usize];
        let mut stack = vec![f.index()];
        while let Some(i) = stack.pop() {
            if i == 0 || seen.insert(i, ()).is_some() {
                continue;
            }
            let n = self.node(i);
            levels[n.level as usize] = true;
            stack.push(n.lo.index());
            stack.push(n.hi.index());
        }
        (0..self.levels).filter(|&l| levels[l as usize]).collect()
    }

    /// The edges at or below the level `cut` that the paths of `f` reach,
    /// with their complement flags, in the order of a walk that takes the 0
    /// child first.
    fn leaves(&self, f: Edge, cut: u32) -> Vec<Edge> {
        let mut seen: Map<Edge, ()> = Map::default();
        let mut found: Map<Edge, ()> = Map::default();
        let mut out = Vec::new();
        let mut stack = vec![f];
        while let Some(e) = stack.pop() {
            let l = self.level(e);
            if l >= cut {
                if found.insert(e, ()).is_none() {
                    out.push(e);
                }
                continue;
            }
            if seen.insert(e, ()).is_some() {
                continue;
            }
            let (lo, hi) = self.cofactors(e, l);
            stack.push(hi);
            stack.push(lo);
        }
        out
    }

    /// The function of the levels above `cut` that is true where the path
    /// of `f` reaches the edge `leaf` at or below `cut`.
    fn indicator(&mut self, f: Edge, cut: u32, leaf: Edge) -> Result<Edge, DdError> {
        let mut done: Map<Edge, Edge> = Map::default();
        let mut stack = vec![f];
        while let Some(&e) = stack.last() {
            let l = self.level(e);
            if l >= cut {
                done.insert(e, if e == leaf { Edge::TRUE } else { Edge::FALSE });
                stack.pop();
                continue;
            }
            if done.contains_key(&e) {
                stack.pop();
                continue;
            }
            let (lo, hi) = self.cofactors(e, l);
            match (done.get(&lo), done.get(&hi)) {
                (Some(&a), Some(&b)) => {
                    let r = self.mk(l, a, b)?;
                    done.insert(e, r);
                    stack.pop();
                }
                (a, b) => {
                    if b.is_none() {
                        stack.push(hi);
                    }
                    if a.is_none() {
                        stack.push(lo);
                    }
                }
            }
        }
        Ok(done[&f])
    }

    // ------------------------------------------------------------ evaluator

    fn and_rec(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.run(Call::And(a, b))
    }

    fn or_rec(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        Ok(self.run(Call::And(a.not(), b.not()))?.not())
    }

    fn ite_rec(&mut self, f: Edge, g: Edge, h: Edge) -> Result<Edge, DdError> {
        let x = self.and_rec(f, g)?;
        let y = self.and_rec(f.not(), h)?;
        self.or_rec(x, y)
    }

    fn xor_rec(&mut self, a: Edge, b: Edge) -> Result<Edge, DdError> {
        self.run(Call::Xor(a, b))
    }

    fn exists_rec(&mut self, f: Edge, cube: Edge) -> Result<Edge, DdError> {
        self.run(Call::Exists(f, cube))
    }

    fn and_exists_rec(&mut self, f: Edge, g: Edge, cube: Edge) -> Result<Edge, DdError> {
        self.run(Call::AndExists(f, g, cube))
    }

    fn rename_rec(&mut self, f: Edge, map: MapId) -> Result<Edge, DdError> {
        self.run(Call::Rename(f, map))
    }

    /// Runs one operation with an explicit task stack, so that the depth of
    /// a diagram does not use the thread stack.
    fn run(&mut self, call: Call) -> Result<Edge, DdError> {
        let mut tasks = std::mem::take(&mut self.tasks);
        let mut vals = std::mem::take(&mut self.vals);
        tasks.clear();
        vals.clear();
        tasks.push(Task::Call(call));
        let r = self.eval_tasks(&mut tasks, &mut vals);
        self.tasks = tasks;
        self.vals = vals;
        r
    }

    fn eval_tasks(&mut self, tasks: &mut Vec<Task>, vals: &mut Vec<Edge>) -> Result<Edge, DdError> {
        while let Some(t) = tasks.pop() {
            match t {
                Task::Call(c) => self.step(c, tasks, vals)?,
                Task::Node { level, done } => {
                    let hi = pop(vals)?;
                    let lo = pop(vals)?;
                    let r = self.mk(level, lo, hi)?;
                    vals.push(self.finish(done, r));
                }
                Task::Store(done) => {
                    let r = pop(vals)?;
                    vals.push(self.finish(done, r));
                }
                Task::Or => {
                    let y = pop(vals)?;
                    let x = pop(vals)?;
                    tasks.push(Task::Not);
                    tasks.push(Task::Call(Call::And(x.not(), y.not())));
                }
                Task::Not => {
                    let r = pop(vals)?;
                    vals.push(r.not());
                }
                Task::Quant { done, second } => {
                    let r0 = pop(vals)?;
                    if r0 == Edge::TRUE {
                        vals.push(self.finish(done, Edge::TRUE));
                    } else {
                        vals.push(r0);
                        tasks.push(Task::Store(done));
                        tasks.push(Task::Or);
                        tasks.push(Task::Call(second));
                    }
                }
                Task::Rename { level, done } => {
                    let hi = pop(vals)?;
                    let lo = pop(vals)?;
                    if self.level(lo) > level && self.level(hi) > level {
                        let r = self.mk(level, lo, hi)?;
                        vals.push(self.finish(done, r));
                    } else {
                        tasks.push(Task::Store(done));
                        tasks.push(Task::Call(Call::Insert(level, lo, hi)));
                    }
                }
            }
        }
        let r = pop(vals)?;
        if vals.is_empty() {
            Ok(r)
        } else {
            Err(broken("the evaluator ended with more than one value"))
        }
    }

    /// Stores a result in the cache and gives the value for the caller.
    fn finish(&mut self, done: Done, r: Edge) -> Edge {
        if done.regular {
            // `r` is the result for the regular operands.
            self.store(done.key, false, r);
            r.xor_complement(done.neg)
        } else {
            self.store(done.key, done.neg, r);
            r
        }
    }

    /// The first step of one call: a terminal case, a cache hit, or the
    /// tasks for its children.
    fn step(
        &mut self,
        c: Call,
        tasks: &mut Vec<Task>,
        vals: &mut Vec<Edge>,
    ) -> Result<(), DdError> {
        match c {
            Call::And(a, b) => {
                if a == Edge::FALSE || b == Edge::FALSE || a == b.not() {
                    vals.push(Edge::FALSE);
                } else if a == Edge::TRUE || a == b {
                    vals.push(b);
                } else if b == Edge::TRUE {
                    vals.push(a);
                } else {
                    let (key, neg) = key(Op::And, a, b, 0);
                    if let Some(r) = self.cached(&key, neg) {
                        vals.push(r);
                        return Ok(());
                    }
                    let top = self.level(a).min(self.level(b));
                    let (a0, a1) = self.cofactors(a, top);
                    let (b0, b1) = self.cofactors(b, top);
                    let done = Done {
                        key,
                        neg,
                        regular: false,
                    };
                    tasks.push(Task::Node { level: top, done });
                    tasks.push(Task::Call(Call::And(a1, b1)));
                    tasks.push(Task::Call(Call::And(a0, b0)));
                }
            }
            Call::Xor(a, b) => {
                if a == b {
                    vals.push(Edge::FALSE);
                } else if a == b.not() {
                    vals.push(Edge::TRUE);
                } else if a.is_constant() {
                    vals.push(b.xor_complement(a == Edge::TRUE));
                } else if b.is_constant() {
                    vals.push(a.xor_complement(b == Edge::TRUE));
                } else {
                    let (key, neg) = key(Op::Xor, a, b, 0);
                    if let Some(r) = self.cached(&key, neg) {
                        vals.push(r);
                        return Ok(());
                    }
                    let (a, b) = (a.regular(), b.regular());
                    let top = self.level(a).min(self.level(b));
                    let (a0, a1) = self.cofactors(a, top);
                    let (b0, b1) = self.cofactors(b, top);
                    let done = Done {
                        key,
                        neg,
                        regular: true,
                    };
                    tasks.push(Task::Node { level: top, done });
                    tasks.push(Task::Call(Call::Xor(a1, b1)));
                    tasks.push(Task::Call(Call::Xor(a0, b0)));
                }
            }
            Call::Exists(f, cube) => {
                if f.is_constant() {
                    vals.push(f);
                    return Ok(());
                }
                let lf = self.level(f);
                let c = self.skip_cube(cube, lf);
                if c.is_constant() {
                    vals.push(f);
                    return Ok(());
                }
                let (key, neg) = key(Op::Exists, f, c, 0);
                if let Some(r) = self.cached(&key, neg) {
                    vals.push(r);
                    return Ok(());
                }
                let (f0, f1) = self.cofactors(f, lf);
                let done = Done {
                    key,
                    neg,
                    regular: false,
                };
                if self.level(c) == lf {
                    let rest = self.cofactors(c, lf).1;
                    tasks.push(Task::Quant {
                        done,
                        second: Call::Exists(f1, rest),
                    });
                    tasks.push(Task::Call(Call::Exists(f0, rest)));
                } else {
                    tasks.push(Task::Node { level: lf, done });
                    tasks.push(Task::Call(Call::Exists(f1, c)));
                    tasks.push(Task::Call(Call::Exists(f0, c)));
                }
            }
            Call::AndExists(f, g, cube) => {
                if f == Edge::FALSE || g == Edge::FALSE || f == g.not() {
                    vals.push(Edge::FALSE);
                    return Ok(());
                }
                if f == Edge::TRUE || f == g {
                    tasks.push(Task::Call(Call::Exists(g, cube)));
                    return Ok(());
                }
                if g == Edge::TRUE {
                    tasks.push(Task::Call(Call::Exists(f, cube)));
                    return Ok(());
                }
                let top = self.level(f).min(self.level(g));
                let c = self.skip_cube(cube, top);
                if c.is_constant() {
                    tasks.push(Task::Call(Call::And(f, g)));
                    return Ok(());
                }
                let (key, neg) = key(Op::AndExists, f, g, c.raw());
                if let Some(r) = self.cached(&key, neg) {
                    vals.push(r);
                    return Ok(());
                }
                let (f0, f1) = self.cofactors(f, top);
                let (g0, g1) = self.cofactors(g, top);
                let done = Done {
                    key,
                    neg,
                    regular: false,
                };
                if self.level(c) == top {
                    let rest = self.cofactors(c, top).1;
                    tasks.push(Task::Quant {
                        done,
                        second: Call::AndExists(f1, g1, rest),
                    });
                    tasks.push(Task::Call(Call::AndExists(f0, g0, rest)));
                } else {
                    tasks.push(Task::Node { level: top, done });
                    tasks.push(Task::Call(Call::AndExists(f1, g1, c)));
                    tasks.push(Task::Call(Call::AndExists(f0, g0, c)));
                }
            }
            Call::Insert(level, lo, hi) => {
                if lo == hi {
                    vals.push(lo);
                    return Ok(());
                }
                let (ll, lh) = (self.level(lo), self.level(hi));
                if ll > level && lh > level {
                    let r = self.mk(level, lo, hi)?;
                    vals.push(r);
                    return Ok(());
                }
                let (key, neg) = key(Op::Insert, lo, hi, level);
                if let Some(r) = self.cached(&key, neg) {
                    vals.push(r);
                    return Ok(());
                }
                let top = ll.min(lh);
                let done = Done {
                    key,
                    neg,
                    regular: false,
                };
                if top == level {
                    let lo0 = self.cofactors(lo, level).0;
                    let hi1 = self.cofactors(hi, level).1;
                    let r = self.mk(level, lo0, hi1)?;
                    vals.push(self.finish(done, r));
                    return Ok(());
                }
                let (l0, l1) = self.cofactors(lo, top);
                let (h0, h1) = self.cofactors(hi, top);
                tasks.push(Task::Node { level: top, done });
                tasks.push(Task::Call(Call::Insert(level, l1, h1)));
                tasks.push(Task::Call(Call::Insert(level, l0, h0)));
            }
            Call::Rename(f, map) => {
                if f.is_constant() {
                    vals.push(f);
                    return Ok(());
                }
                let (key, neg) = key(Op::Rename, f, Edge::TRUE, map.0);
                if let Some(r) = self.cached(&key, neg) {
                    vals.push(r);
                    return Ok(());
                }
                let n = self.node(f.index());
                let level = self.maps[map.0 as usize][n.level as usize];
                let done = Done {
                    key,
                    neg,
                    regular: true,
                };
                tasks.push(Task::Rename { level, done });
                tasks.push(Task::Call(Call::Rename(n.hi, map)));
                tasks.push(Task::Call(Call::Rename(n.lo, map)));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ queries

    /// The value of `f` for an assignment of the variables.
    pub fn eval(&self, f: Edge, assignment: impl Fn(u32) -> bool) -> Result<bool, DdError> {
        self.check_edges(&[f])?;
        let mut e = f;
        while !e.is_constant() {
            let l = self.level(e);
            let (lo, hi) = self.cofactors(e, l);
            e = if assignment(l) { hi } else { lo };
        }
        Ok(e == Edge::TRUE)
    }

    /// One assignment that makes `f` true, as the levels on one path and
    /// their values. At each node, the 0 child comes first. Levels that are
    /// not in the list can have each value. A false `f` gives `None`.
    pub fn pick_one(&self, f: Edge) -> Result<Option<Vec<(u32, bool)>>, DdError> {
        self.check_edges(&[f])?;
        if f == Edge::FALSE {
            return Ok(None);
        }
        let mut out = Vec::new();
        let mut e = f;
        while !e.is_constant() {
            let l = self.level(e);
            let (lo, hi) = self.cofactors(e, l);
            if lo != Edge::FALSE {
                out.push((l, false));
                e = lo;
            } else {
                out.push((l, true));
                e = hi;
            }
        }
        Ok(Some(out))
    }

    /// The number of assignments of all levels that make `f` true. The
    /// arena must have at most 127 levels.
    pub fn sat_count(&self, f: Edge) -> Result<u128, DdError> {
        self.check_edges(&[f])?;
        if self.levels > 127 {
            return Err(DdError::LevelOutOfRange {
                level: self.levels,
                levels: 128,
            });
        }
        let mut memo: Map<u32, u128> = Map::default();
        let c = self.count_rec(f.regular(), &mut memo);
        let l = self.level_or_end(f);
        let below = 1u128 << (self.levels - l);
        let c = if f.is_complement() { below - c } else { c };
        Ok(c << l)
    }

    fn level_or_end(&self, e: Edge) -> u32 {
        self.level(e).min(self.levels)
    }

    /// The number of assignments of the levels from the level of the
    /// regular edge `e` to the last level that make `e` true.
    fn count_rec(&self, e: Edge, memo: &mut Map<u32, u128>) -> u128 {
        if e.is_constant() {
            return 1;
        }
        if let Some(&c) = memo.get(&e.index()) {
            return c;
        }
        let n = self.node(e.index());
        let mut total = 0;
        for child in [n.lo, n.hi] {
            let cl = self.level_or_end(child);
            let below = 1u128 << (self.levels - cl);
            let c = self.count_rec(child.regular(), memo);
            let c = if child.is_complement() { below - c } else { c };
            total += c << (cl - n.level - 1);
        }
        memo.insert(e.index(), total);
        total
    }

    /// The number of distinct nodes of `f`, with the terminal node.
    pub fn size(&self, f: Edge) -> Result<usize, DdError> {
        self.check_edges(&[f])?;
        let mut seen: Map<u32, ()> = Map::default();
        let mut stack = vec![f.index()];
        while let Some(i) = stack.pop() {
            if seen.insert(i, ()).is_some() {
                continue;
            }
            if i != 0 {
                let n = self.node(i);
                stack.push(n.lo.index());
                stack.push(n.hi.index());
            }
        }
        Ok(seen.len())
    }
}

/// One operation of the evaluator.
#[derive(Clone, Copy, Debug)]
enum Call {
    And(Edge, Edge),
    Xor(Edge, Edge),
    Exists(Edge, Edge),
    AndExists(Edge, Edge, Edge),
    Rename(Edge, MapId),
    /// If the variable at the level then the 1 function else the 0
    /// function: `Insert(level, lo, hi)`.
    Insert(u32, Edge, Edge),
}

/// How a finished result goes into the cache and to the caller.
#[derive(Clone, Copy, Debug)]
struct Done {
    key: Key,
    neg: bool,
    /// True if the result is for the regular operands, and the caller gets
    /// it complemented by `neg`.
    regular: bool,
}

/// One task of the evaluator. The values of finished calls are on a value
/// stack.
#[derive(Clone, Copy, Debug)]
enum Task {
    Call(Call),
    /// Pops the 1 child and the 0 child and makes the node.
    Node {
        level: u32,
        done: Done,
    },
    /// Pops a result and stores it.
    Store(Done),
    /// Pops 2 values and computes their disjunction.
    Or,
    /// Pops a value and complements it.
    Not,
    /// Pops the result of the 0 child of a quantified level. If it is not
    /// true, computes `second` and the disjunction.
    Quant {
        done: Done,
        second: Call,
    },
    /// Pops the renamed 1 child and 0 child and joins them at `level`.
    Rename {
        level: u32,
        done: Done,
    },
}

fn pop(vals: &mut Vec<Edge>) -> Result<Edge, DdError> {
    vals.pop()
        .ok_or_else(|| broken("the evaluator has no value to take"))
}

/// One public operation and its operands, for the shadow check.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum ShadowOp {
    Var(u32),
    Cube(Vec<u32>),
    And(Edge, Edge),
    Or(Edge, Edge),
    Xor(Edge, Edge),
    Diff(Edge, Edge),
    Ite(Edge, Edge, Edge),
    Exists(Edge, Edge),
    AndExists(Edge, Edge, Edge),
    Rename(Edge, MapId),
    Literals(Vec<(u32, bool)>),
    /// A copy from another arena. The shadow check does not apply.
    Import,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frozen arena with 3 levels and the nodes `x0 and x1` and `x1`.
    fn good() -> Vec<Node> {
        vec![
            TERMINAL,
            Node {
                level: 1,
                lo: Edge::FALSE,
                hi: Edge::TRUE,
            },
            Node {
                level: 0,
                lo: Edge::FALSE,
                hi: Edge::new(1, false),
            },
        ]
    }

    fn frozen(nodes: Vec<Node>) -> Frozen {
        let unique = nodes
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, n)| (*n, i as u32))
            .collect();
        Frozen {
            levels: 3,
            nodes,
            unique,
        }
    }

    fn rejected(f: &Frozen, text: &str) {
        match f.validate() {
            Err(DdError::InvariantBroken(d)) => assert!(d.contains(text), "{d}"),
            other => panic!("the validator gave {other:?}, not a fault with {text:?}"),
        }
    }

    #[test]
    fn the_validator_accepts_a_good_arena() {
        assert_eq!(frozen(good()).validate(), Ok(()));
    }

    #[test]
    fn the_validator_rejects_each_fault() {
        let mut n = good();
        n[2].hi = n[2].hi.not();
        rejected(&frozen(n), "complemented 1 edge");

        let mut n = good();
        n[1].lo = Edge::TRUE;
        rejected(&frozen(n), "2 equal edges");

        let mut n = good();
        n[2].level = 2;
        rejected(&frozen(n), "not at a higher level");

        let mut n = good();
        n[2].hi = Edge::new(9, false);
        rejected(&frozen(n), "not in the arena");

        let mut n = good();
        n[1].level = 3;
        rejected(&frozen(n), "has level 3");

        let mut f = frozen(good());
        f.unique.remove(&f.nodes[2].clone());
        rejected(&f, "not in the unique table");

        let mut n = good();
        n.push(n[2]);
        let mut f = frozen(n);
        f.unique.insert(f.nodes[2], 2);
        rejected(&f, "not in the unique table");

        let mut f = frozen(good());
        f.unique.insert(
            Node {
                level: 2,
                lo: Edge::FALSE,
                hi: Edge::TRUE,
            },
            7,
        );
        rejected(&f, "entries with no node");

        let mut n = good();
        n[0].level = 0;
        rejected(&frozen(n), "terminal");
    }

    #[test]
    fn the_validator_rejects_a_scratch_node_that_is_in_the_frozen_arena() {
        let f = Arc::new(frozen(good()));
        let mut dd = Dd::scratch(Arc::clone(&f), None);
        dd.nodes.push(f.nodes[1]);
        dd.unique.insert(f.nodes[1], 3);
        match dd.validate() {
            Err(DdError::InvariantBroken(d)) => assert!(d.contains("duplicate"), "{d}"),
            other => panic!("the validator gave {other:?}"),
        }
    }
}
