//! magma-graph — resource DAG construction over `magma_types::ResourceAddress`.
//!
//! Built on `petgraph`. Yields wave structure (Kahn's algorithm) for the
//! apply engine — each wave is a partial-order batch that may apply in
//! parallel. Per `theory/MAGMA.md` §II.1, this is the *resource* graph;
//! the *operation* graph (EvaluatePangea → Plan → Apply → …) is a
//! `shigoto::Dag` in magma-apply (§II.9).

use std::collections::HashMap;

use magma_types::ResourceAddress;
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("cycle detected in resource graph: {0:?}")]
    CycleDetected(Vec<ResourceAddress>),
    #[error("dependency edge references missing node: {0:?}")]
    MissingNode(ResourceAddress),
}

// ── Waves ──────────────────────────────────────────────────────────

/// One antichain of the resource DAG: a set of addresses with **no
/// dependency edges among them**, so every member may be applied
/// concurrently with every other member.
///
/// Deliberately NOT `IntoIterator` and NOT `Deref<Target = Vec<_>>`.
/// Both would put `.flatten()` back within easy reach, and flattening the
/// wave decomposition is exactly the defect this type exists to prevent —
/// it computes the available parallelism and then throws it away. Read a
/// wave with [`Wave::iter`]; ask for its width with [`Wave::len`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave(Vec<ResourceAddress>);

impl Wave {
    /// Borrow the addresses in this wave. Order within a wave is
    /// deterministic (sorted by `(type, name)`) but carries **no**
    /// dependency meaning — that is what makes the wave concurrent.
    pub fn iter(&self) -> std::slice::Iter<'_, ResourceAddress> {
        self.0.iter()
    }

    /// How many addresses may run concurrently at this depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow as a slice, for callers that need indexed access.
    #[must_use]
    pub fn as_slice(&self) -> &[ResourceAddress] {
        &self.0
    }
}

// NOTE: `Wave` deliberately implements NEITHER `IntoIterator` (by value or
// by reference) NOR `Deref<Target = [_]>`.
//
// With `impl IntoIterator for &Wave`, the expression
// `waves.iter().flatten()` type-checks — `Iterator::flatten` only needs its
// Item to be `IntoIterator` — and the whole decomposition collapses again in
// six characters. Without it, that expression does not compile, and a caller
// who truly wants every address must write `.flat_map(Wave::iter)`, which
// names what it is doing and greps as one token.
//
// Indexed access below is safe to expose: unlike `IntoIterator`/`Deref` it
// offers no route to a whole-collection `.flatten()`.
impl std::ops::Index<usize> for Wave {
    type Output = ResourceAddress;
    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

/// The full topological wave decomposition of a resource DAG — the
/// dependency-ordered sequence of concurrent batches.
///
/// **Why this is a newtype and not `Vec<Vec<ResourceAddress>>`.** The
/// decomposition's whole value is the *width* of each wave: the set of
/// changes that may safely run at once. A caller that writes
/// `waves.into_iter().flatten().collect()` gets a correct sequential order
/// and silently discards every bit of that parallelism — which is precisely
/// what the apply engine did until the wave loop landed, and precisely the
/// kind of regression that reads as harmless in review.
///
/// So there is no `IntoIterator<Item = ResourceAddress>`, no
/// `Deref<Target = Vec<_>>`, and no public inner field: the *accidental*
/// flatten does not compile. A caller that genuinely wants a linear order
/// — magma-apply's provider-free structural apply, which really is
/// sequential — asks for it by name via [`Waves::into_sequential_order`],
/// which is greppable and self-documenting at the call site.
///
/// Tier-honest: this makes the *accident* unrepresentable. A determined
/// caller can still write `.iter().flat_map(Wave::iter).cloned()`; that is
/// a deliberate, explicit act, not a slip. Sealing *deliberate* flattening
/// is not possible in the type system and is not claimed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waves(Vec<Wave>);

impl Waves {
    /// Iterate the waves in dependency order. Wave `i` may not begin until
    /// every wave `< i` is complete; within a wave, order is free.
    pub fn iter(&self) -> std::slice::Iter<'_, Wave> {
        self.0.iter()
    }

    /// Number of waves — the DAG's critical-path length in edges + 1.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Total addresses across every wave.
    #[must_use]
    pub fn total(&self) -> usize {
        self.0.iter().map(Wave::len).sum()
    }

    /// The widest wave — the maximum concurrency this graph ever offers.
    /// A useful ceiling: no executor can usefully run more workers than
    /// this, however large its budget.
    #[must_use]
    pub fn max_width(&self) -> usize {
        self.0.iter().map(Wave::len).max().unwrap_or(0)
    }

    /// Borrow wave `i`, if it exists.
    #[must_use]
    pub fn wave(&self, i: usize) -> Option<&Wave> {
        self.0.get(i)
    }

    /// **Deliberately** collapse the decomposition into one dependency-
    /// respecting sequential order, discarding wave width.
    ///
    /// Named rather than implicit so that discarding the parallelism is a
    /// visible choice at the call site. Correct only for an executor that
    /// is genuinely sequential by construction — magma-apply's structural,
    /// provider-free apply is the one such caller in the workspace.
    #[must_use]
    pub fn into_sequential_order(self) -> Vec<ResourceAddress> {
        self.0.into_iter().flat_map(|w| w.0).collect()
    }

    /// No waves at all — nothing to do.
    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// A fully sequential decomposition: **one address per wave**, in the
    /// given order.
    ///
    /// This is the correct degradation when dependency structure is
    /// unavailable (e.g. `waves()` returned a cycle error and the caller
    /// still wants to attempt the apply in plan order). Note what it is
    /// *not*: putting every address into a single wide wave. That would
    /// assert an antichain — "none of these depend on each other" — which
    /// is exactly the fact that just failed to be established, and a
    /// concurrent executor would act on the assertion by running
    /// mutually-dependent changes at once. One-per-wave costs all the
    /// parallelism and preserves ordering; a single wave would do the
    /// reverse.
    #[must_use]
    pub fn sequential(addresses: impl IntoIterator<Item = ResourceAddress>) -> Self {
        Self(addresses.into_iter().map(|a| Wave(vec![a])).collect())
    }

    /// Build from raw waves. Crate-internal: the only legitimate producer
    /// is [`ResourceGraph::waves`], whose Kahn partition establishes the
    /// antichain property every consumer relies on.
    fn from_raw(raw: Vec<Vec<ResourceAddress>>) -> Self {
        Self(raw.into_iter().map(Wave).collect())
    }
}

impl<'a> IntoIterator for &'a Waves {
    type Item = &'a Wave;
    type IntoIter = std::slice::Iter<'a, Wave>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl std::ops::Index<usize> for Waves {
    type Output = Wave;
    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

// ── ResourceGraph ──────────────────────────────────────────────────

/// Typed DAG over resource addresses. Edges go `from → to` where
/// `to depends_on from` (i.e. `from` must be applied before `to`).
#[derive(Debug, Default, Clone)]
pub struct ResourceGraph {
    inner: DiGraph<ResourceAddress, ()>,
    index: HashMap<ResourceAddress, NodeIndex>,
}

impl ResourceGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resource address; idempotent.
    pub fn add(&mut self, addr: ResourceAddress) -> NodeIndex {
        if let Some(idx) = self.index.get(&addr) {
            return *idx;
        }
        let idx = self.inner.add_node(addr.clone());
        self.index.insert(addr, idx);
        idx
    }

    /// Add a dependency `to` depends on `from`. Both ends are created
    /// on demand if missing.
    pub fn depend(&mut self, dependent: ResourceAddress, dependency: ResourceAddress) {
        let from = self.add(dependency);
        let to = self.add(dependent);
        self.inner.add_edge(from, to, ());
    }

    /// Number of nodes (resources).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.node_count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.node_count() == 0
    }

    /// Detect cycles. Returns the first cycle's nodes if one is present.
    /// Does `dependent` depend on `dependency`, directly or transitively?
    ///
    /// Transitive, not just a direct edge: `a → b → c` means `c` really does
    /// depend on `a`, and an ordering check that missed that would pass a
    /// graph it should reject. Exists so the antichain property of a wave —
    /// the thing any concurrent executor rests on — can be **asserted against
    /// the graph** rather than inferred from trusting Kahn's construction.
    #[must_use]
    pub fn depends_on(&self, dependent: &ResourceAddress, dependency: &ResourceAddress) -> bool {
        let (Some(&to), Some(&from)) = (self.index.get(dependent), self.index.get(dependency))
        else {
            return false;
        };
        // Edges run `from → to` where `to depends_on from`, so a dependency
        // path is a path from `dependency` to `dependent`.
        petgraph::algo::has_path_connecting(&self.inner, from, to, None)
    }

    pub fn detect_cycle(&self) -> Option<Vec<ResourceAddress>> {
        match petgraph::algo::toposort(&self.inner, None) {
            Ok(_) => None,
            Err(cycle) => {
                let bad = cycle.node_id();
                Some(vec![self.inner[bad].clone()])
            }
        }
    }

    /// Kahn-style wave partitioning. Each wave is the set of nodes
    /// whose in-edges are all satisfied by prior waves. Nodes within a
    /// wave have no inter-dependencies and may apply concurrently.
    ///
    /// Returns the opaque [`Waves`] rather than `Vec<Vec<_>>` so the
    /// parallelism this computes cannot be discarded by accident — see
    /// [`Waves`] for why that matters.
    pub fn waves(&self) -> Result<Waves, GraphError> {
        if let Some(cycle) = self.detect_cycle() {
            return Err(GraphError::CycleDetected(cycle));
        }

        let mut indegree: HashMap<NodeIndex, usize> = self
            .inner
            .node_indices()
            .map(|n| (n, self.inner.edges_directed(n, Direction::Incoming).count()))
            .collect();

        let mut waves: Vec<Vec<ResourceAddress>> = Vec::new();
        let mut remaining: usize = self.inner.node_count();

        while remaining > 0 {
            let mut current: Vec<NodeIndex> = indegree
                .iter()
                .filter(|&(_, &d)| d == 0)
                .map(|(n, _)| *n)
                .collect();
            if current.is_empty() {
                // No zero-indegree nodes but remaining > 0 → cycle.
                let stuck: Vec<ResourceAddress> =
                    indegree.keys().map(|n| self.inner[*n].clone()).collect();
                return Err(GraphError::CycleDetected(stuck));
            }
            // Sort for deterministic output.
            current.sort_by_key(|n| {
                let a = &self.inner[*n];
                (a.type_id.0.clone(), a.name.clone())
            });

            let wave: Vec<ResourceAddress> =
                current.iter().map(|n| self.inner[*n].clone()).collect();
            waves.push(wave);

            for n in &current {
                indegree.remove(n);
                let neighbors: Vec<NodeIndex> = self
                    .inner
                    .edges_directed(*n, Direction::Outgoing)
                    .map(|e| e.target())
                    .collect();
                for m in neighbors {
                    if let Some(d) = indegree.get_mut(&m) {
                        *d = d.saturating_sub(1);
                    }
                }
            }
            remaining -= current.len();
        }

        Ok(Waves::from_raw(waves))
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{InstanceKey, ModulePath, ResourceKind, ResourceTypeId};

    fn addr(name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("aws_vpc".into()),
            name: name.into(),
            key: None,
        }
    }

    /// I4 — the decomposition reports the parallelism it found.
    ///
    /// `max_width` is the whole reason waves are not flattened: it is the
    /// structural ceiling on how many changes may ever run at once. A
    /// flattened order reports 1 here and the information is gone.
    #[test]
    fn waves_report_the_width_a_flatten_would_have_discarded() {
        let mut g = ResourceGraph::new();
        //   a          wave 0: {a}        width 1
        //  / \         wave 1: {b, c}     width 2
        // b   c        wave 2: {d}        width 1
        //  \ /
        //   d
        g.depend(addr("b"), addr("a"));
        g.depend(addr("c"), addr("a"));
        g.depend(addr("d"), addr("b"));
        g.depend(addr("d"), addr("c"));
        let waves = g.waves().unwrap();

        assert_eq!(waves.max_width(), 2, "the diamond's middle wave is width 2");
        assert_eq!(waves.total(), 4);
        assert_eq!(waves.len(), 3, "critical path is 3 waves deep");

        // The sequential collapse is still available — by name — and still
        // respects dependency order.
        let linear = waves.into_sequential_order();
        assert_eq!(linear.len(), 4);
        let pos = |n: &str| linear.iter().position(|a| a.name == n).unwrap();
        assert!(pos("a") < pos("b") && pos("a") < pos("c"));
        assert!(pos("b") < pos("d") && pos("c") < pos("d"));
    }

    /// The graph-error degradation must not manufacture an antichain.
    ///
    /// When `waves()` fails (cycle), a caller may still want to attempt the
    /// apply in plan order. Putting every address into ONE wave would assert
    /// "none of these depend on each other" — precisely the fact that just
    /// failed to be established — and a concurrent executor would act on that
    /// assertion by running mutually-dependent changes simultaneously.
    /// `sequential` gives one address per wave instead: all the ordering, none
    /// of the false parallelism.
    #[test]
    fn sequential_degradation_is_one_per_wave_never_one_wide_wave() {
        let ws = Waves::sequential([addr("a"), addr("b"), addr("c")]);
        assert_eq!(ws.len(), 3, "three waves, not one");
        assert_eq!(
            ws.max_width(),
            1,
            "a fallback must never claim addresses of unknown dependency are concurrent"
        );
        assert_eq!(ws.total(), 3);
        assert_eq!(ws[0][0].name, "a");
        assert_eq!(ws[2][0].name, "c");
    }

    #[test]
    fn empty_waves_are_empty() {
        let ws = Waves::empty();
        assert!(ws.is_empty());
        assert_eq!(ws.total(), 0);
        assert_eq!(ws.max_width(), 0);
        assert!(ws.into_sequential_order().is_empty());
    }

    /// Every member of a wave is mutually independent — the property the
    /// concurrent executor would rely on. Verified directly against the
    /// graph's own edges rather than assumed from Kahn's construction.
    #[test]
    fn a_wave_is_an_antichain() {
        let mut g = ResourceGraph::new();
        g.depend(addr("b"), addr("a"));
        g.depend(addr("c"), addr("a"));
        g.depend(addr("d"), addr("a"));
        let waves = g.waves().unwrap();
        let middle = waves.wave(1).expect("second wave exists");
        assert_eq!(middle.len(), 3, "b, c, d are all free once a lands");
        // None of b/c/d depends on another of b/c/d: each has exactly the one
        // incoming edge from `a`, so no pair is ordered.
        for x in middle.iter() {
            for y in middle.iter() {
                if x != y {
                    assert!(
                        !g.depends_on(x, y),
                        "{:?} must not depend on {:?} inside one wave",
                        x.name,
                        y.name
                    );
                }
            }
        }
    }

    #[test]
    fn empty_graph_yields_no_waves() {
        let g = ResourceGraph::new();
        let waves = g.waves().unwrap();
        assert!(waves.is_empty());
    }

    #[test]
    fn linear_chain_collapses_into_n_waves() {
        let mut g = ResourceGraph::new();
        // a → b → c
        g.depend(addr("b"), addr("a"));
        g.depend(addr("c"), addr("b"));
        let waves = g.waves().unwrap();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0][0].name, "a");
        assert_eq!(waves[1][0].name, "b");
        assert_eq!(waves[2][0].name, "c");
    }

    #[test]
    fn independent_nodes_apply_in_one_wave() {
        let mut g = ResourceGraph::new();
        g.add(addr("a"));
        g.add(addr("b"));
        g.add(addr("c"));
        let waves = g.waves().unwrap();
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 3);
    }

    #[test]
    fn diamond_resolves_to_three_waves() {
        let mut g = ResourceGraph::new();
        //   a
        //  / \
        // b   c
        //  \ /
        //   d
        g.depend(addr("b"), addr("a"));
        g.depend(addr("c"), addr("a"));
        g.depend(addr("d"), addr("b"));
        g.depend(addr("d"), addr("c"));
        let waves = g.waves().unwrap();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0][0].name, "a");
        assert_eq!(waves[1].len(), 2);
        assert_eq!(waves[2][0].name, "d");
    }

    #[test]
    fn cycle_detected() {
        let mut g = ResourceGraph::new();
        g.depend(addr("a"), addr("b"));
        g.depend(addr("b"), addr("a"));
        let err = g.waves().unwrap_err();
        assert!(matches!(err, GraphError::CycleDetected(_)));
    }

    #[test]
    fn instance_key_distinguishes_nodes() {
        let mut g = ResourceGraph::new();
        let mut a = addr("a");
        a.key = Some(InstanceKey::Index(0));
        let mut b = addr("a");
        b.key = Some(InstanceKey::Index(1));
        g.add(a);
        g.add(b);
        assert_eq!(g.len(), 2);
    }
}
