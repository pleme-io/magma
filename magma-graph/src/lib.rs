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
    pub fn waves(&self) -> Result<Vec<Vec<ResourceAddress>>, GraphError> {
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

        Ok(waves)
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
