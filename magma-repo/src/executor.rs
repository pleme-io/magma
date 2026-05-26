//! Typed per-workspace executor trait.
//!
//! `PangeaRepoReconciler` doesn't know how to plan/apply a single
//! workspace — that's `MagmaExecutor`'s job in pangea-operator,
//! or a Mock executor in tests. This trait is the seam: implement
//! it, hand a `Arc<dyn WorkspaceExecutor>` to
//! `PangeaRepoReconciler::with_executor`, and apply() drives the
//! whole repo per-workspace.
//!
//! Same direction as `magma_test_laws::ApplyMetrics` —
//! abstraction-by-trait so magma-repo compiles without the
//! operator's full magma library suite.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::DiscoveredWorkspace;

/// What executing one workspace produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceExecutionResult {
    /// Bundle id (BLAKE3 hex) that magma_bundle::Bundle emitted
    /// for this workspace's reconcile. `None` when the executor
    /// didn't emit a bundle (e.g. dry-run / skipped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    pub applied: usize,
    pub failed: usize,
    /// Final lifecycle phase per magma_fsm::Phase as Debug string
    /// (Stable / Refused / Approving / Failed). Operator-side
    /// consumers route on this for CR status surfaces.
    pub phase: String,
    /// Optional error string. When present, the executor refused
    /// or failed; the operator-side reconciler should respect
    /// the ReconcilePolicy.on_failure setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceExecutorError {
    #[error("execute failed: {0}")]
    Execute(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Per-workspace executor. magma-repo calls this for every
/// workspace in dep-order on each repo apply cycle.
#[async_trait]
pub trait WorkspaceExecutor: Send + Sync {
    /// Drive a reconcile cycle (render → plan → apply) for one
    /// workspace and return the typed result. Errors here halt
    /// the repo-level apply per ReconcilePolicy (M2.x).
    async fn execute(
        &self,
        workspace: &DiscoveredWorkspace,
    ) -> Result<WorkspaceExecutionResult, WorkspaceExecutorError>;
}

/// Always-skip executor — useful in tests + for "dry-run"
/// reconciles where the operator wants to observe state without
/// applying.
pub struct DryRunExecutor;

#[async_trait]
impl WorkspaceExecutor for DryRunExecutor {
    async fn execute(
        &self,
        _workspace: &DiscoveredWorkspace,
    ) -> Result<WorkspaceExecutionResult, WorkspaceExecutorError> {
        Ok(WorkspaceExecutionResult {
            bundle_id: None,
            applied: 0,
            failed: 0,
            phase: "Idle".into(),
            error: None,
        })
    }
}
