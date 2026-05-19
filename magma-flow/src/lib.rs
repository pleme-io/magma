//! magma-flow — typed Pangea cross-workspace flow runner.
//!
//! One canonical implementation of:
//!
//! * `FlowFile` — the on-disk shape `magma flow run` consumes (and the
//!   `pangea_orchestrate` MCP tool, and `Pangea::Magma::Chain`'s
//!   `reconcile_all` output).
//! * `OptimizationHints` — typed orchestration hints (strategy,
//!   max_concurrency, retries, timeout).
//! * `topological_order` — deterministic execution order across
//!   declared cross-workspace edges.
//! * `run` — the plan-only execution engine that loads each
//!   workspace, plans against current state, propagates outputs along
//!   typed edges, and emits the AggregateReport.
//!
//! Before this crate landed, FlowFile + topo + plan-loop were
//! duplicated in magma-cli (CLI binary) and magma-mcp (MCP server).
//! Per Pillar 12 (generation over composition) — every cross-workspace
//! caller now reaches the same engine.
//!
//! Per `theory/PANGEA-MAGMA-ORCHESTRATION.md` §IV.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use magma_backend::Backend as _;
use magma_pangea::WorkspaceLoader as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FlowError {
    #[error("flow references unknown workspace: {0}")]
    UnknownWorkspace(String),
    #[error("flow has a cycle (involving: {0:?})")]
    Cycle(Vec<String>),
    #[error("workspace {workspace}: {stage}: {message}")]
    WorkspaceStep {
        workspace: String,
        stage:     &'static str,
        message:   String,
    },
}

// ── Typed flow shape ──────────────────────────────────────────────

/// One workspace in the flow — a name + a directory containing a
/// Pangea-rendered (or hand-authored) Terraform JSON workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowWorkspace {
    pub name: String,
    pub dir:  PathBuf,
}

/// A typed cross-workspace edge: `from.{from_output}` flows to
/// `to.{to_input}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEdge {
    pub from:        String,
    pub from_output: String,
    pub to:          String,
    pub to_input:    String,
}

/// Typed orchestration hints. M0.4 plumbed; honored by the
/// shigoto-wrapped apply path once `magma flow run` lands its
/// scheduler integration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimizationHints {
    #[serde(default)]
    pub strategy:         Option<String>,
    #[serde(default)]
    pub max_concurrency:  Option<usize>,
    #[serde(default)]
    pub retries:          Option<OptimizationRetries>,
    #[serde(default)]
    pub timeout_ms:       Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimizationRetries {
    #[serde(default)]
    pub max:        Option<u32>,
    #[serde(default)]
    pub backoff_ms: Option<u64>,
}

/// The full typed flow shape. `magma flow run <flow.json>` reads it
/// from disk; `pangea_orchestrate` accepts it as a JSON-RPC param;
/// `Pangea::Magma::Chain#reconcile_all` emits it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFile {
    pub workspaces: Vec<FlowWorkspace>,
    #[serde(default)]
    pub edges:      Vec<FlowEdge>,
    #[serde(default)]
    pub optimization: Option<OptimizationHints>,
}

// ── Topological order ─────────────────────────────────────────────

/// Stable Kahn-style topological order over the declared edges.
/// Returns `FlowError::UnknownWorkspace` if any edge references a
/// name not in `workspaces`, and `FlowError::Cycle` if the graph
/// can't be linearized.
pub fn topological_order(flow: &FlowFile) -> Result<Vec<String>, FlowError> {
    let mut indegree: HashMap<String, usize> = flow
        .workspaces
        .iter()
        .map(|w| (w.name.clone(), 0))
        .collect();
    for edge in &flow.edges {
        if !indegree.contains_key(&edge.from) {
            return Err(FlowError::UnknownWorkspace(edge.from.clone()));
        }
        if !indegree.contains_key(&edge.to) {
            return Err(FlowError::UnknownWorkspace(edge.to.clone()));
        }
        *indegree.entry(edge.to.clone()).or_insert(0) += 1;
    }
    let mut queue: VecDeque<String> = indegree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(n, _)| n.clone())
        .collect();
    // Stable order: process queue in declaration order.
    queue = flow
        .workspaces
        .iter()
        .filter(|w| queue.contains(&w.name))
        .map(|w| w.name.clone())
        .collect();
    let mut order: Vec<String> = vec![];
    let mut visited: HashSet<String> = HashSet::new();
    while let Some(n) = queue.pop_front() {
        if !visited.insert(n.clone()) {
            continue;
        }
        order.push(n.clone());
        for edge in flow.edges.iter().filter(|e| e.from == n) {
            if let Some(d) = indegree.get_mut(&edge.to) {
                *d = d.saturating_sub(1);
                if *d == 0 {
                    queue.push_back(edge.to.clone());
                }
            }
        }
    }
    if order.len() < flow.workspaces.len() {
        let stuck: Vec<String> = indegree
            .into_iter()
            .filter(|(name, _)| !visited.contains(name))
            .map(|(name, _)| name)
            .collect();
        return Err(FlowError::Cycle(stuck));
    }
    Ok(order)
}

// ── Aggregate report ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceSummary {
    pub workspace: String,
    pub plan_id:   String,
    pub changes:   usize,
    pub outputs:   HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AggregateReport {
    pub workspaces: Vec<WorkspaceSummary>,
    pub propagated: HashMap<String, serde_json::Value>,
}

// ── Engine ────────────────────────────────────────────────────────

/// Run a flow plan-only: discover + load + plan each workspace in
/// topological order, propagate outputs along declared edges, emit
/// an AggregateReport. Per `theory/PANGEA-MAGMA-ORCHESTRATION.md` §IV.
///
/// The current implementation is sequential regardless of
/// `flow.optimization` — the shigoto-wrapped apply path lands those
/// hints. Until then this engine is the single canonical Pangea
/// cross-workspace plan loop; both `magma flow` and
/// `pangea_orchestrate` route through it.
pub async fn run(flow: &FlowFile) -> Result<AggregateReport, FlowError> {
    let order = topological_order(flow)?;

    let mut propagated: HashMap<String, serde_json::Value> = HashMap::new();
    let mut summaries: Vec<WorkspaceSummary> = vec![];

    for ws_name in order {
        let entry = flow
            .workspaces
            .iter()
            .find(|w| w.name == ws_name)
            .ok_or_else(|| FlowError::UnknownWorkspace(ws_name.clone()))?;

        let shape = magma_pangea::WorkspaceShape::discover(&entry.dir)
            .map_err(|e| FlowError::WorkspaceStep {
                workspace: entry.name.clone(),
                stage:     "discover",
                message:   e.to_string(),
            })?;
        let loaded = magma_pangea::TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| FlowError::WorkspaceStep {
                workspace: entry.name.clone(),
                stage:     "load",
                message:   e.to_string(),
            })?;
        let cfg = magma_config::Config::from_json(loaded.rendered.clone())
            .map_err(|e| FlowError::WorkspaceStep {
                workspace: entry.name.clone(),
                stage:     "parse",
                message:   e.to_string(),
            })?;
        let backend = magma_backend::LocalBackend::new(entry.dir.clone());
        let state = backend
            .read_state()
            .await
            .map_err(|e| FlowError::WorkspaceStep {
                workspace: entry.name.clone(),
                stage:     "read_state",
                message:   e.to_string(),
            })?;
        let plan = magma_plan::plan(&cfg, &state)
            .map_err(|e| FlowError::WorkspaceStep {
                workspace: entry.name.clone(),
                stage:     "plan",
                message:   e.to_string(),
            })?;

        let mut workspace_outputs: HashMap<String, serde_json::Value> = HashMap::new();
        for (out_name, decl) in &cfg.outputs {
            workspace_outputs.insert(out_name.clone(), decl.value.clone());
        }
        for edge in flow.edges.iter().filter(|e| e.from == entry.name) {
            if let Some(v) = workspace_outputs.get(&edge.from_output) {
                propagated.insert(
                    format!("{}.{}", edge.to, edge.to_input),
                    v.clone(),
                );
            }
        }

        summaries.push(WorkspaceSummary {
            workspace: entry.name.clone(),
            plan_id:   hex::encode(plan.id.0),
            changes:   plan.resource_changes.len(),
            outputs:   workspace_outputs,
        });
    }

    Ok(AggregateReport {
        workspaces: summaries,
        propagated,
    })
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ws(name: &str, dir: &str) -> FlowWorkspace {
        FlowWorkspace {
            name: name.into(),
            dir:  PathBuf::from(dir),
        }
    }
    fn edge(from: &str, from_out: &str, to: &str, to_in: &str) -> FlowEdge {
        FlowEdge {
            from:        from.into(),
            from_output: from_out.into(),
            to:          to.into(),
            to_input:    to_in.into(),
        }
    }

    #[test]
    fn topological_order_linear_chain() {
        let flow = FlowFile {
            workspaces: vec![ws("a", "/a"), ws("b", "/b"), ws("c", "/c")],
            edges:      vec![edge("a", "x", "b", "x"), edge("b", "y", "c", "y")],
            optimization: None,
        };
        let order = topological_order(&flow).unwrap();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn topological_order_preserves_declaration_order_among_roots() {
        let flow = FlowFile {
            workspaces: vec![ws("first", "/f"), ws("second", "/s"), ws("third", "/t")],
            edges:      vec![],
            optimization: None,
        };
        let order = topological_order(&flow).unwrap();
        assert_eq!(order, vec!["first", "second", "third"]);
    }

    #[test]
    fn topological_order_detects_cycle() {
        let flow = FlowFile {
            workspaces: vec![ws("a", "/a"), ws("b", "/b")],
            edges:      vec![edge("a", "x", "b", "x"), edge("b", "y", "a", "y")],
            optimization: None,
        };
        match topological_order(&flow) {
            Err(FlowError::Cycle(_)) => {}
            other => panic!("expected Cycle, got {other:?}"),
        }
    }

    #[test]
    fn topological_order_rejects_unknown_workspace() {
        let flow = FlowFile {
            workspaces: vec![ws("a", "/a")],
            edges:      vec![edge("a", "x", "ghost", "x")],
            optimization: None,
        };
        match topological_order(&flow) {
            Err(FlowError::UnknownWorkspace(n)) => assert_eq!(n, "ghost"),
            other => panic!("expected UnknownWorkspace, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_propagates_outputs_along_edges() {
        use magma_fixtures::TfJsonBuilder;

        let tmp = tempfile::tempdir().unwrap();
        let vpc_dir     = tmp.path().join("vpc");
        let cluster_dir = tmp.path().join("cluster");

        TfJsonBuilder::new()
            .resource("aws_vpc", "net", serde_json::json!({"cidr_block": "10.0.0.0/16"}))
            .output("vpc_id", serde_json::json!("vpc-flow-test"))
            .render_to_dir(&vpc_dir).unwrap();
        TfJsonBuilder::new()
            .resource("aws_iam_role", "node", serde_json::json!({"name": "n"}))
            .render_to_dir(&cluster_dir).unwrap();

        let flow = FlowFile {
            workspaces: vec![
                FlowWorkspace { name: "vpc".into(),     dir: vpc_dir.clone() },
                FlowWorkspace { name: "cluster".into(), dir: cluster_dir.clone() },
            ],
            edges: vec![FlowEdge {
                from:        "vpc".into(),
                from_output: "vpc_id".into(),
                to:          "cluster".into(),
                to_input:    "vpc_id".into(),
            }],
            optimization: None,
        };

        let report = run(&flow).await.unwrap();
        assert_eq!(
            report.workspaces.iter().map(|s| s.workspace.clone()).collect::<Vec<_>>(),
            vec!["vpc", "cluster"]
        );
        assert_eq!(
            report.propagated.get("cluster.vpc_id"),
            Some(&serde_json::Value::String("vpc-flow-test".into())),
        );
    }

    // ── proptest: topological_order over random DAGs ─────────────
    //
    // Generates random directed acyclic graphs with up to 6
    // workspaces + up to 10 edges (validated DAGs by construction:
    // edges only point from lower-index to higher-index nodes), and
    // asserts:
    //   1. Every produced order is a permutation of the workspace
    //      names (no duplicates, no losses).
    //   2. Every edge from→to in the input has from appearing before
    //      to in the output order (the defining topo property).
    //   3. Determinism: two calls on the same input produce identical
    //      output.
    //
    // Plus a separate property: any cycle reliably returns
    // FlowError::Cycle.

    use proptest::prelude::*;

    fn dag_strategy() -> impl Strategy<Value = FlowFile> {
        proptest::collection::vec("[a-z][a-z0-9]{0,4}", 2..=6).prop_flat_map(|names| {
            // Dedup names to avoid HashMap collisions; ensure at
            // least 2 unique nodes survive (caller's strategy
            // doesn't guarantee that after dedup).
            let unique: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                let mut v: Vec<_> = names.into_iter().filter(|n| seen.insert(n.clone())).collect();
                while v.len() < 2 {
                    v.push(format!("node{}", v.len()));
                }
                v
            };
            let n = unique.len();
            // Inherently-acyclic edge generator: pick `lo ∈ 0..(n-1)`
            // then `hi ∈ (lo+1)..n`. Every produced pair has
            // lo < hi strictly, so the resulting graph is upper-
            // triangular and DAG by construction. No rejection
            // sampling, no proptest local-reject pressure.
            let edge_strategy = proptest::collection::vec(
                (0..(n - 1)).prop_flat_map(move |lo| {
                    ((lo + 1)..n).prop_map(move |hi| (lo, hi))
                }),
                0..=(n * 2),
            );
            (Just(unique), edge_strategy).prop_map(|(names, edges)| {
                FlowFile {
                    workspaces: names.iter().map(|n| FlowWorkspace {
                        name: n.clone(),
                        dir:  std::path::PathBuf::from(format!("/tmp/{n}")),
                    }).collect(),
                    edges: edges.into_iter().map(|(a, b)| FlowEdge {
                        from:        names[a].clone(),
                        from_output: "out".into(),
                        to:          names[b].clone(),
                        to_input:    "in".into(),
                    }).collect(),
                    optimization: None,
                }
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn topo_is_permutation_of_workspaces(flow in dag_strategy()) {
            let order = topological_order(&flow).unwrap();
            let want: std::collections::HashSet<String> = flow
                .workspaces.iter().map(|w| w.name.clone()).collect();
            let got: std::collections::HashSet<String> = order.iter().cloned().collect();
            prop_assert_eq!(got, want);
            prop_assert_eq!(order.len(), flow.workspaces.len());
        }

        #[test]
        fn topo_respects_every_edge(flow in dag_strategy()) {
            let order = topological_order(&flow).unwrap();
            let position: std::collections::HashMap<String, usize> =
                order.iter().enumerate().map(|(i, n)| (n.clone(), i)).collect();
            for edge in &flow.edges {
                let from_pos = position[&edge.from];
                let to_pos   = position[&edge.to];
                prop_assert!(from_pos < to_pos,
                    "edge {}→{} violates topo: from={from_pos} to={to_pos}",
                    edge.from, edge.to);
            }
        }

        #[test]
        fn topo_is_deterministic(flow in dag_strategy()) {
            let a = topological_order(&flow).unwrap();
            let b = topological_order(&flow).unwrap();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn topo_detects_synthetic_cycle(
            names in proptest::collection::vec("[a-z][a-z0-9]{0,4}", 2..=4)
        ) {
            // Dedup names; build a complete cycle a → b → c → … → a.
            let unique: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                names.into_iter().filter(|n| seen.insert(n.clone())).collect()
            };
            prop_assume!(unique.len() >= 2);

            let mut edges = Vec::new();
            for i in 0..unique.len() {
                let j = (i + 1) % unique.len();
                edges.push(FlowEdge {
                    from:        unique[i].clone(),
                    from_output: "o".into(),
                    to:          unique[j].clone(),
                    to_input:    "i".into(),
                });
            }
            let flow = FlowFile {
                workspaces: unique.iter().map(|n| FlowWorkspace {
                    name: n.clone(),
                    dir:  std::path::PathBuf::from("/tmp/x"),
                }).collect(),
                edges,
                optimization: None,
            };
            match topological_order(&flow) {
                Err(FlowError::Cycle(_)) => {}
                other => panic!("expected Cycle, got {other:?}"),
            }
        }
    }
}
