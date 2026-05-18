//! `WorkspaceChain` — typed DAG of workspaces with cross-workspace
//! data flow.
//!
//! Per theory/MAGMA.md §II.9, chains thread upstream outputs into
//! downstream inputs as typed Rust values. The chain is reconciled in
//! topological order; each workspace runs once, its outputs feed the
//! next, no disk roundtrips happen between workspaces.
//!
//! Two reconciliation modes:
//!
//! - `reconcile_all` — run the entire chain. Operators get the full
//!   constellation deploy in one in-memory invocation.
//! - `reconcile_subset` — run a subset, taking stubbed outputs for
//!   upstream nodes that aren't in the subset. Lets each workspace be
//!   tested in isolation while its declared upstream edges are
//!   validated by the chain shape.

use std::collections::HashMap;
use std::sync::Arc;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::workspace::{ReconcileResult, Workspace, WorkspaceError};
use magma_types::State;

// ── ChainEdge ──────────────────────────────────────────────────────

/// A directed edge in a `WorkspaceChain` — wires an upstream
/// workspace's output slot to a downstream workspace's input slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainEdge {
    pub from:        String,
    pub from_output: String,
    pub to:          String,
    pub to_input:    String,
}

// ── WorkspaceChain ─────────────────────────────────────────────────

/// Typed DAG of `Workspace`s + `ChainEdge`s wiring outputs to inputs.
#[derive(Default)]
pub struct WorkspaceChain {
    nodes: HashMap<String, Arc<dyn Workspace>>,
    edges: Vec<ChainEdge>,
}

impl WorkspaceChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a workspace. Idempotent on name (re-adding overwrites).
    pub fn add(&mut self, workspace: Arc<dyn Workspace>) -> &mut Self {
        self.nodes.insert(workspace.name().to_string(), workspace);
        self
    }

    /// Wire an upstream output to a downstream input.
    pub fn link(&mut self, edge: ChainEdge) -> &mut Self {
        self.edges.push(edge);
        self
    }

    #[must_use]
    pub fn node_count(&self) -> usize { self.nodes.len() }
    #[must_use]
    pub fn edge_count(&self) -> usize { self.edges.len() }

    /// Topological-order reconciliation. Outputs from upstream nodes
    /// flow into downstream inputs as typed Rust values. Returns one
    /// `ReconcileResult` per workspace, keyed by workspace name.
    pub async fn reconcile_all(
        &self,
        external_inputs: HashMap<String, HashMap<String, serde_json::Value>>,
        initial_states: HashMap<String, State>,
    ) -> Result<HashMap<String, ReconcileResult>, WorkspaceError> {
        self.reconcile_with_stubs(
            &self.topo_order()?,
            external_inputs,
            HashMap::new(),
            initial_states,
        )
        .await
    }

    /// Reconcile a subset of workspaces. Upstream outputs that aren't
    /// reconciled in this run are taken from `stub_upstream_outputs`.
    /// Lets you test one workspace's behavior with predecessor outputs
    /// mocked, while the chain's wiring is still validated.
    pub async fn reconcile_subset(
        &self,
        subset_names: &[String],
        external_inputs: HashMap<String, HashMap<String, serde_json::Value>>,
        stub_upstream_outputs: HashMap<String, HashMap<String, serde_json::Value>>,
        initial_states: HashMap<String, State>,
    ) -> Result<HashMap<String, ReconcileResult>, WorkspaceError> {
        let order = self.topo_order()?;
        let order: Vec<String> = order
            .into_iter()
            .filter(|n| subset_names.contains(n))
            .collect();
        self.reconcile_with_stubs(
            &order,
            external_inputs,
            stub_upstream_outputs,
            initial_states,
        )
        .await
    }

    async fn reconcile_with_stubs(
        &self,
        order: &[String],
        external_inputs: HashMap<String, HashMap<String, serde_json::Value>>,
        stub_upstream_outputs: HashMap<String, HashMap<String, serde_json::Value>>,
        initial_states: HashMap<String, State>,
    ) -> Result<HashMap<String, ReconcileResult>, WorkspaceError> {
        let mut outputs_so_far: HashMap<String, HashMap<String, serde_json::Value>> =
            stub_upstream_outputs;
        let mut results: HashMap<String, ReconcileResult> = HashMap::new();

        for ws_name in order {
            let workspace = self.nodes.get(ws_name).ok_or_else(|| {
                WorkspaceError::InvalidChain(format!(
                    "topo order names unknown workspace: {ws_name:?}",
                ))
            })?;

            let mut inputs = external_inputs
                .get(ws_name)
                .cloned()
                .unwrap_or_default();
            for edge in self.edges.iter().filter(|e| e.to == *ws_name) {
                if let Some(upstream_outputs) = outputs_so_far.get(&edge.from) {
                    if let Some(value) = upstream_outputs.get(&edge.from_output) {
                        inputs.insert(edge.to_input.clone(), value.clone());
                    }
                }
            }

            let state = initial_states
                .get(ws_name)
                .cloned()
                .unwrap_or_else(magma_state::empty_state);
            let result = workspace.reconcile(&inputs, state).await?;
            outputs_so_far.insert(ws_name.clone(), result.outputs.clone());
            results.insert(ws_name.clone(), result);
        }
        Ok(results)
    }

    /// Compute the topological order of the chain. Errors on cycles or
    /// edges pointing at unknown workspaces.
    pub fn topo_order(&self) -> Result<Vec<String>, WorkspaceError> {
        let mut graph: DiGraph<String, ()> = DiGraph::new();
        let mut indices: HashMap<String, NodeIndex> = HashMap::new();
        for name in self.nodes.keys() {
            let idx = graph.add_node(name.clone());
            indices.insert(name.clone(), idx);
        }
        for edge in &self.edges {
            let from_idx = indices.get(&edge.from).ok_or_else(|| {
                WorkspaceError::InvalidChain(format!(
                    "edge.from references unknown workspace: {:?}",
                    edge.from,
                ))
            })?;
            let to_idx = indices.get(&edge.to).ok_or_else(|| {
                WorkspaceError::InvalidChain(format!(
                    "edge.to references unknown workspace: {:?}",
                    edge.to,
                ))
            })?;
            graph.add_edge(*from_idx, *to_idx, ());
        }
        let order = petgraph::algo::toposort(&graph, None).map_err(|cycle| {
            WorkspaceError::InvalidChain(format!(
                "cycle in chain at workspace: {:?}",
                graph[cycle.node_id()],
            ))
        })?;
        Ok(order.into_iter().map(|idx| graph[idx].clone()).collect())
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::InlineWorkspace;
    use magma_config::Config;
    use serde_json::json;

    fn vpc_ws() -> Arc<dyn Workspace> {
        Arc::new(InlineWorkspace::new(
            "vpc",
            vec![],
            vec!["vpc_id".into()],
            |_| {
                Config::from_json(json!({
                    "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
                }))
                .map_err(WorkspaceError::Config)
            },
            |_cfg, _state| HashMap::from([("vpc_id".to_string(), json!("vpc-test-001"))]),
        ))
    }

    fn subnet_ws() -> Arc<dyn Workspace> {
        Arc::new(InlineWorkspace::new(
            "subnet",
            vec!["vpc_id".into()],
            vec!["subnet_id".into()],
            |inputs| {
                let vpc_id = inputs.get("vpc_id").cloned().unwrap_or(json!(""));
                Config::from_json(json!({
                    "resource": {
                        "aws_subnet": {
                            "public": { "vpc_id": vpc_id, "cidr_block": "10.0.1.0/24" }
                        }
                    }
                }))
                .map_err(WorkspaceError::Config)
            },
            |cfg, _state| {
                let vpc_id = cfg.resources.get("aws_subnet")
                    .and_then(|m| m.get("public"))
                    .and_then(|s| s.get("vpc_id"))
                    .cloned()
                    .unwrap_or(json!(""));
                HashMap::from([
                    ("subnet_id".to_string(), json!("subnet-test-001")),
                    ("upstream_vpc_id".to_string(), vpc_id),
                ])
            },
        ))
    }

    #[test]
    fn cycle_detected() {
        let mut chain = WorkspaceChain::new();
        chain.add(vpc_ws()).add(subnet_ws());
        chain.link(ChainEdge {
            from: "vpc".into(), from_output: "vpc_id".into(),
            to: "subnet".into(), to_input: "vpc_id".into(),
        });
        chain.link(ChainEdge {
            from: "subnet".into(), from_output: "subnet_id".into(),
            to: "vpc".into(), to_input: "back_edge".into(),
        });
        let err = chain.topo_order().unwrap_err();
        assert!(matches!(err, WorkspaceError::InvalidChain(_)));
    }

    #[test]
    fn unknown_target_errors() {
        let mut chain = WorkspaceChain::new();
        chain.add(vpc_ws());
        chain.link(ChainEdge {
            from: "vpc".into(), from_output: "vpc_id".into(),
            to: "nope".into(), to_input: "vpc_id".into(),
        });
        let err = chain.topo_order().unwrap_err();
        assert!(matches!(err, WorkspaceError::InvalidChain(_)));
    }

    #[tokio::test]
    async fn chain_topo_order_works() {
        let mut chain = WorkspaceChain::new();
        chain.add(vpc_ws()).add(subnet_ws());
        chain.link(ChainEdge {
            from: "vpc".into(), from_output: "vpc_id".into(),
            to: "subnet".into(), to_input: "vpc_id".into(),
        });
        let order = chain.topo_order().unwrap();
        assert_eq!(order, vec!["vpc".to_string(), "subnet".to_string()]);
    }
}
