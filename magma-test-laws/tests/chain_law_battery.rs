//! Integration test: typical multi-workspace chains pass the
//! universal chain laws.

#![cfg(feature = "chain-laws")]

use std::path::PathBuf;

use magma_flow::{FlowEdge, FlowFile, FlowWorkspace, OptimizationHints};
use magma_test_laws::chain::*;

fn ws(name: &str) -> FlowWorkspace {
    FlowWorkspace { name: name.into(), dir: PathBuf::from(format!("workspaces/{name}")) }
}

fn edge(from: &str, from_out: &str, to: &str, to_in: &str) -> FlowEdge {
    FlowEdge {
        from:        from.into(),
        from_output: from_out.into(),
        to:          to.into(),
        to_input:    to_in.into(),
    }
}

// ── Property 1: a well-formed chain passes ────────────────────────

#[test]
fn three_workspace_chain_passes_all_laws() {
    let f = FlowFile {
        workspaces: vec![ws("vpc"), ws("cluster"), ws("apps")],
        edges: vec![
            edge("vpc",     "vpc_id",   "cluster", "vpc_id"),
            edge("cluster", "endpoint", "apps",    "k8s_endpoint"),
        ],
        optimization: None,
    };
    assert_all_laws(&f);
    let order = apply_order(&f);
    assert_eq!(order, vec!["vpc", "cluster", "apps"]);
    let destroy = destroy_order(&f);
    assert_eq!(destroy, vec!["apps", "cluster", "vpc"]);
}

// ── Property 2: empty chain is vacuously valid ────────────────────

#[test]
fn empty_chain_passes() {
    let f = FlowFile::default();
    assert_all_laws(&f);
    assert_eq!(apply_order(&f).len(), 0);
}

// ── Property 3: cycle is caught ───────────────────────────────────

#[test]
#[should_panic(expected = "Chain law violated: chain is not acyclic")]
fn cycle_is_caught() {
    let f = FlowFile {
        workspaces: vec![ws("a"), ws("b")],
        edges: vec![
            edge("a", "out", "b", "in"),
            edge("b", "out", "a", "in"), // creates cycle
        ],
        optimization: None,
    };
    assert_acyclic(&f);
}

// ── Property 4: edge to undeclared workspace is caught ────────────

#[test]
#[should_panic(expected = "edge references undeclared workspace")]
fn undeclared_workspace_in_edge_is_caught() {
    let f = FlowFile {
        workspaces: vec![ws("a")],
        edges: vec![edge("a", "out", "ghost", "in")],
        optimization: None,
    };
    assert_edges_reference_declared_workspaces(&f);
}

// ── Property 5: duplicate workspace names are caught ──────────────

#[test]
#[should_panic(expected = "duplicate workspace name")]
fn duplicate_workspace_name_is_caught() {
    let f = FlowFile {
        workspaces: vec![ws("a"), ws("a")],
        edges: vec![],
        optimization: None,
    };
    assert_workspace_names_unique(&f);
}

// ── Property 6: optimization zero-knobs are caught ────────────────

#[test]
#[should_panic(expected = "max_concurrency is 0")]
fn zero_concurrency_is_caught() {
    let f = FlowFile {
        workspaces: vec![ws("a")],
        edges: vec![],
        optimization: Some(OptimizationHints {
            max_concurrency: Some(0),
            ..Default::default()
        }),
    };
    assert_optimization_concurrency_positive(&f);
}

#[test]
#[should_panic(expected = "timeout_ms is 0")]
fn zero_timeout_is_caught() {
    let f = FlowFile {
        workspaces: vec![ws("a")],
        edges: vec![],
        optimization: Some(OptimizationHints {
            timeout_ms: Some(0),
            ..Default::default()
        }),
    };
    assert_optimization_concurrency_positive(&f);
}

// ── Property 7: diamond chain is acyclic ──────────────────────────

#[test]
fn diamond_chain_passes() {
    // root → a → leaf
    // root → b → leaf
    let f = FlowFile {
        workspaces: vec![ws("root"), ws("a"), ws("b"), ws("leaf")],
        edges: vec![
            edge("root", "out", "a",    "in"),
            edge("root", "out", "b",    "in"),
            edge("a",    "out", "leaf", "in_a"),
            edge("b",    "out", "leaf", "in_b"),
        ],
        optimization: None,
    };
    assert_all_laws(&f);
    let order = apply_order(&f);
    // root must be first, leaf last.
    assert_eq!(order.first().unwrap(), "root");
    assert_eq!(order.last().unwrap(),  "leaf");
}
