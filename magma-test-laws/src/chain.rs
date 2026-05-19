//! Reusable laws for multi-workspace chains (magma-flow FlowFile).
//!
//! A chain is a DAG of workspaces with typed cross-workspace edges
//! (one workspace's typed output flows into another's typed input).
//! Pangea-rendered constellation.json + fleet.yaml both parse into
//! FlowFile.
//!
//! Laws every well-formed chain must satisfy:
//! 1. Acyclic — `topological_order` succeeds.
//! 2. Every edge endpoint is a declared workspace.
//! 3. No orphan edges referencing workspaces not in the file.
//! 4. Workspace names are unique within the chain.
//! 5. Empty chain (0 workspaces) is vacuously valid.
//!
//! Gated behind `chain-laws`. Per `theory/MAGMA.md` §V.7
//! (constellation orchestration).

use std::collections::HashSet;

use magma_flow::{topological_order, FlowFile};

// ── Law 1: acyclic ────────────────────────────────────────────────

pub fn assert_acyclic(flow: &FlowFile) {
    if let Err(e) = topological_order(flow) {
        panic!("Chain law violated: chain is not acyclic — {e:?}");
    }
}

// ── Law 2 + 3: edges reference declared workspaces ────────────────

pub fn assert_edges_reference_declared_workspaces(flow: &FlowFile) {
    let declared: HashSet<&str> = flow.workspaces.iter().map(|w| w.name.as_str()).collect();
    for e in &flow.edges {
        assert!(
            declared.contains(e.from.as_str()),
            "Chain law violated: edge references undeclared workspace `{}` (from-side); declared: {declared:?}",
            e.from,
        );
        assert!(
            declared.contains(e.to.as_str()),
            "Chain law violated: edge references undeclared workspace `{}` (to-side); declared: {declared:?}",
            e.to,
        );
    }
}

// ── Law 4: workspace names are unique ─────────────────────────────

pub fn assert_workspace_names_unique(flow: &FlowFile) {
    let mut seen = HashSet::new();
    for w in &flow.workspaces {
        assert!(
            seen.insert(w.name.as_str()),
            "Chain law violated: duplicate workspace name `{}`",
            w.name,
        );
    }
}

// ── Law 5: every workspace has a non-empty dir ────────────────────

pub fn assert_workspace_dirs_nonempty(flow: &FlowFile) {
    for w in &flow.workspaces {
        let s = w.dir.as_os_str();
        assert!(
            !s.is_empty(),
            "Chain law violated: workspace `{}` has empty dir",
            w.name,
        );
    }
}

// ── Law 6: optimization.max_concurrency is positive when present ──

pub fn assert_optimization_concurrency_positive(flow: &FlowFile) {
    if let Some(opt) = &flow.optimization {
        if let Some(max) = opt.max_concurrency {
            assert!(
                max > 0,
                "Chain law violated: optimization.max_concurrency is 0 (would never run anything)",
            );
        }
        if let Some(timeout) = opt.timeout_ms {
            assert!(
                timeout > 0,
                "Chain law violated: optimization.timeout_ms is 0 (would always timeout)",
            );
        }
    }
}

// ── Composite ─────────────────────────────────────────────────────

pub fn assert_all_laws(flow: &FlowFile) {
    assert_acyclic(flow);
    assert_edges_reference_declared_workspaces(flow);
    assert_workspace_names_unique(flow);
    assert_workspace_dirs_nonempty(flow);
    assert_optimization_concurrency_positive(flow);
}

// ── Helper: produce the topological apply order ───────────────────

/// Return the apply order — first workspace in the vec applies
/// first. Convenience over `magma_flow::topological_order` that
/// panics rather than returns a Result for inline test use.
pub fn apply_order(flow: &FlowFile) -> Vec<String> {
    topological_order(flow).unwrap_or_else(|e| {
        panic!("apply_order: chain not topologically orderable: {e:?}")
    })
}

/// Reverse-apply order is the destroy order — last applied is
/// destroyed first. Convenience helper.
pub fn destroy_order(flow: &FlowFile) -> Vec<String> {
    let mut o = apply_order(flow);
    o.reverse();
    o
}
