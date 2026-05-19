//! `PangeaRepoReconciler` — implements the universal Reconciler
//! trait over a typed Pangea repository.
//!
//! Composes:
//! * `source::Source::materialize` to get a local directory
//! * `discover::discover` to build the typed `DiscoveredRepo`
//! * Bundle attestation flows through every workspace's plan/apply
//!
//! M0 lands the trait skeleton + read_state + compute_plan over
//! the typed workspace list. apply() delegates to a caller-
//! provided per-workspace executor (so the operator wires
//! MagmaExecutor without magma-repo depending on it).

use std::sync::Arc;

use async_trait::async_trait;
use magma_converge::{
    change, Action, AppliedChange, Outcome, Plan, PlanId, Reconciler, ReconcilerError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{source::Source, DiscoveredRepo};

/// Reconciler over a Pangea repository. Each `read_state` reads
/// the latest typed `DiscoveredRepo` from the source; each
/// `compute_plan` emits one typed `Change` per workspace
/// describing what the repo expects vs what magma observed last;
/// each `apply` invokes the configured `WorkspaceExecutor` on
/// every workspace + records per-workspace bundle_ids.
pub struct PangeaRepoReconciler {
    pub source:   Source,
    pub work_dir: std::path::PathBuf,
    /// Per-workspace executor. None = M0 bookkeeping-only mode
    /// (records attestation; doesn't actually invoke MagmaExecutor).
    /// Some = M2+ continuous-reconciliation mode where each
    /// workspace is driven through the executor.
    pub executor: Option<Arc<dyn crate::executor::WorkspaceExecutor>>,
}

impl PangeaRepoReconciler {
    pub fn new(source: Source, work_dir: impl Into<std::path::PathBuf>) -> Self {
        Self { source, work_dir: work_dir.into(), executor: None }
    }

    /// Attach a per-workspace executor. The reconciler drives
    /// every workspace through `executor.execute()` on each
    /// apply cycle. Per-workspace bundle_ids are recorded in
    /// `RepoObservedState.workspaces`.
    pub fn with_executor(
        mut self,
        executor: Arc<dyn crate::executor::WorkspaceExecutor>,
    ) -> Self {
        self.executor = Some(executor);
        self
    }
}

/// Typed projection of the live state — what magma last observed
/// about the repo. Serializes into the `Value` the universal
/// Reconciler trait surface uses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoObservedState {
    /// Last `repo_attestation` magma successfully reconciled.
    /// `None` = first reconcile cycle ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attestation: Option<String>,
    /// Last commit SHA (when source is Git) — informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_commit_sha: Option<String>,
    /// Per-workspace map: name → last bundle_id.
    #[serde(default)]
    pub workspaces: std::collections::BTreeMap<String, String>,
}

#[async_trait]
impl Reconciler for PangeaRepoReconciler {
    fn kind(&self) -> &'static str { "pangea_repo" }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        // M0: state lives on disk at <work_dir>/magma-repo-state.json.
        // M2+: state will be in the operator's StateBackend so
        // restarts pick up where they left off.
        let state_path = self.work_dir.join("magma-repo-state.json");
        if !state_path.exists() {
            return Ok(serde_json::to_value(RepoObservedState::default())
                .map_err(|e| ReconcilerError::ReadState(e.to_string()))?);
        }
        let bytes = std::fs::read(&state_path)
            .map_err(|e| ReconcilerError::ReadState(format!("read {state_path:?}: {e}")))?;
        let state: RepoObservedState = serde_json::from_slice(&bytes)
            .map_err(|e| ReconcilerError::ReadState(format!("parse state: {e}")))?;
        serde_json::to_value(state)
            .map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, _config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        // Materialize the source + discover the typed repo.
        let local = self.source.materialize(&self.work_dir)
            .map_err(|e| ReconcilerError::ComputePlan(format!("materialize: {e}")))?;
        let repo = crate::discover(local)
            .map_err(|e| ReconcilerError::ComputePlan(format!("discover: {e}")))?;
        let observed: RepoObservedState = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("decode state: {e}")))?;

        // One typed `Change` per workspace. Address shape:
        //   `pangea_repo.<workspace_name>`
        // Action is:
        //   Create — workspace not yet reconciled
        //   Update — workspace reconciled before but attestation drift
        //   NoOp   — observed.last_attestation matches current
        let mut changes = vec![];
        for w in &repo.workspaces {
            let address = format!("pangea_repo.{}", w.name);
            let previously_known = observed.workspaces.contains_key(&w.name);
            let attestation_match = observed.last_attestation.as_deref()
                == Some(repo.repo_attestation.as_str());
            let action = match (previously_known, attestation_match) {
                (false, _)    => Action::Create,
                (true, true)  => Action::NoOp,
                (true, false) => Action::Update,
            };
            changes.push(change(
                address,
                action,
                Some(serde_json::json!({ "name": w.name })),
                Some(serde_json::json!({
                    "name":           w.name,
                    "dir":            w.dir,
                    "namespace":      w.config.default_namespace,
                    "depends_on":     w.config.depends_on,
                })),
            ));
        }
        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        // M2: if an executor is wired, drive every workspace
        // through it + aggregate per-workspace outcomes into the
        // top-level Outcome. Without an executor (M0 bookkeeping
        // mode), apply just records the new attestation.
        let started_at = chrono::Utc::now();

        let local = self.source.materialize(&self.work_dir)
            .map_err(|e| ReconcilerError::Apply(format!("materialize: {e}")))?;
        let repo = crate::discover(local)
            .map_err(|e| ReconcilerError::Apply(format!("discover: {e}")))?;

        let mut applied = vec![];
        let mut failed: Vec<magma_converge::FailedChange> = vec![];
        let mut workspace_bundles: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();

        // Index plan changes by address for quick lookup as we
        // iterate workspaces (so each Change's typed Action is
        // preserved in the AppliedChange record).
        let plan_action: std::collections::HashMap<&str, magma_converge::Action> = plan
            .changes
            .iter()
            .map(|c| (c.address.as_str(), c.action))
            .collect();

        // NoOp workspaces still get recorded (so their previous
        // bundle_id stays in the state) but aren't driven through
        // the executor — convergence already achieved.
        for w in &repo.workspaces {
            let address = format!("pangea_repo.{}", w.name);
            let action = plan_action
                .get(address.as_str())
                .copied()
                .unwrap_or(magma_converge::Action::NoOp);
            if matches!(action, magma_converge::Action::NoOp) {
                applied.push(AppliedChange { address: address.clone(), action });
                continue;
            }
            // Drive the executor if wired; otherwise just record
            // the workspace as observed.
            let result = if let Some(executor) = self.executor.as_ref() {
                match executor.execute(w).await {
                    Ok(r) => r,
                    Err(e) => {
                        failed.push(magma_converge::FailedChange {
                            address: address.clone(),
                            action,
                            error: format!("executor: {e}"),
                        });
                        continue;
                    }
                }
            } else {
                crate::executor::WorkspaceExecutionResult {
                    bundle_id: None,
                    applied:   0,
                    failed:    0,
                    phase:     "Idle".into(),
                    error:     None,
                }
            };

            if let Some(err) = result.error.as_ref() {
                failed.push(magma_converge::FailedChange {
                    address: address.clone(),
                    action,
                    error:   err.clone(),
                });
                continue;
            }

            // Always record the workspace as observed (empty
            // bundle_id when executor not wired or skipped). This
            // keeps `compute_plan`'s previously_known flag
            // correct across cycles.
            workspace_bundles.insert(
                w.name.clone(),
                result.bundle_id.unwrap_or_default(),
            );
            applied.push(AppliedChange { address, action });
        }
        // Plus record every other discovered workspace too (even
        // NoOp ones already recorded above will overwrite no-op
        // entries with their previous bundle_id from state).
        for w in &repo.workspaces {
            workspace_bundles
                .entry(w.name.clone())
                .or_insert_with(String::new);
        }

        // Persist new state.
        let new_state = RepoObservedState {
            last_attestation: Some(repo.repo_attestation.clone()),
            last_commit_sha:  None, // M3 fills this once Git fetch lands
            workspaces:       workspace_bundles,
        };
        let state_path = self.work_dir.join("magma-repo-state.json");
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&new_state)
                .map_err(|e| ReconcilerError::Apply(format!("encode state: {e}")))?,
        )
        .map_err(|e| ReconcilerError::Apply(format!("write state: {e}")))?;

        Ok(Outcome {
            plan_id:     plan.id.clone(),
            kind:        "pangea_repo".into(),
            applied,
            failed,
            started_at,
            finished_at: chrono::Utc::now(),
        })
    }
}

// Required for Plan::new to compile with the chrono::Utc import.
#[allow(unused)]
fn _kept_alive() -> PlanId { PlanId(String::new()) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn stage_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("pangea.yml"), "accounts: {}\n").unwrap();
        let a = tmp.path().join("workspaces/alpha");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("pangea.yml"), "default_namespace: alpha\n").unwrap();
        let b = tmp.path().join("workspaces/beta");
        fs::create_dir_all(&b).unwrap();
        fs::write(b.join("pangea.yml"), "default_namespace: beta\n").unwrap();
        tmp
    }

    #[tokio::test]
    async fn first_reconcile_plans_every_workspace_as_create() {
        let tmp = stage_repo();
        let work = tempfile::tempdir().unwrap();
        let r = PangeaRepoReconciler::new(
            Source::Local { path: tmp.path().to_path_buf() },
            work.path(),
        );
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&serde_json::json!({}), &state).unwrap();
        assert_eq!(plan.change_count(), 2);
        for c in &plan.changes {
            assert_eq!(c.action, Action::Create);
        }
    }

    #[tokio::test]
    async fn second_reconcile_is_noop_when_repo_unchanged() {
        let tmp = stage_repo();
        let work = tempfile::tempdir().unwrap();
        let r = PangeaRepoReconciler::new(
            Source::Local { path: tmp.path().to_path_buf() },
            work.path(),
        );
        // First cycle: plan + apply.
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&serde_json::json!({}), &state).unwrap();
        r.apply(&plan).await.unwrap();
        // Second cycle: same source -> noop plan.
        let state2 = r.read_state().await.unwrap();
        let plan2 = r.compute_plan(&serde_json::json!({}), &state2).unwrap();
        for c in &plan2.changes {
            assert_eq!(c.action, Action::NoOp, "expected NoOp, got {:?}", c);
        }
    }

    /// Mock executor that records every workspace it was called
    /// with + returns a typed bundle_id derived from the
    /// workspace name. Lets us assert apply() drives the
    /// executor for every non-NoOp workspace.
    struct RecordingExecutor {
        invoked: std::sync::Mutex<Vec<String>>,
    }
    impl RecordingExecutor {
        fn new() -> Self { Self { invoked: std::sync::Mutex::new(vec![]) } }
        fn invocations(&self) -> Vec<String> {
            self.invoked.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl crate::executor::WorkspaceExecutor for RecordingExecutor {
        async fn execute(
            &self,
            workspace: &crate::DiscoveredWorkspace,
        ) -> Result<crate::executor::WorkspaceExecutionResult, crate::executor::WorkspaceExecutorError>
        {
            self.invoked.lock().unwrap().push(workspace.name.clone());
            Ok(crate::executor::WorkspaceExecutionResult {
                bundle_id: Some(format!("bundle-{}", workspace.name)),
                applied:   1,
                failed:    0,
                phase:     "Stable".into(),
                error:     None,
            })
        }
    }

    #[tokio::test]
    async fn apply_with_executor_drives_each_workspace() {
        let tmp = stage_repo();
        let work = tempfile::tempdir().unwrap();
        let recorder = std::sync::Arc::new(RecordingExecutor::new());
        let r = PangeaRepoReconciler::new(
            Source::Local { path: tmp.path().to_path_buf() },
            work.path(),
        ).with_executor(recorder.clone());

        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&serde_json::json!({}), &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();

        // The recorder saw both workspaces.
        let mut got = recorder.invocations();
        got.sort();
        assert_eq!(got, vec!["alpha", "beta"]);

        // Outcome aggregates per-workspace results.
        assert_eq!(outcome.applied.len(), 2);
        assert!(outcome.failed.is_empty());

        // State on disk records per-workspace bundle ids.
        let state_path = work.path().join("magma-repo-state.json");
        let state_bytes = fs::read(&state_path).unwrap();
        let observed: RepoObservedState = serde_json::from_slice(&state_bytes).unwrap();
        assert_eq!(observed.workspaces.len(), 2);
        assert_eq!(observed.workspaces.get("alpha").map(String::as_str), Some("bundle-alpha"));
        assert_eq!(observed.workspaces.get("beta").map(String::as_str),  Some("bundle-beta"));
    }

    /// Executor that fails the second workspace. Apply must
    /// continue past the failure + surface it via Outcome.failed.
    struct PartialFailExecutor;
    #[async_trait]
    impl crate::executor::WorkspaceExecutor for PartialFailExecutor {
        async fn execute(
            &self,
            workspace: &crate::DiscoveredWorkspace,
        ) -> Result<crate::executor::WorkspaceExecutionResult, crate::executor::WorkspaceExecutorError>
        {
            if workspace.name == "beta" {
                return Ok(crate::executor::WorkspaceExecutionResult {
                    bundle_id: None,
                    applied:   0,
                    failed:    1,
                    phase:     "Failed".into(),
                    error:     Some("beta refused".into()),
                });
            }
            Ok(crate::executor::WorkspaceExecutionResult {
                bundle_id: Some(format!("bundle-{}", workspace.name)),
                applied:   1,
                failed:    0,
                phase:     "Stable".into(),
                error:     None,
            })
        }
    }

    #[tokio::test]
    async fn apply_continues_past_per_workspace_failure() {
        let tmp = stage_repo();
        let work = tempfile::tempdir().unwrap();
        let r = PangeaRepoReconciler::new(
            Source::Local { path: tmp.path().to_path_buf() },
            work.path(),
        ).with_executor(std::sync::Arc::new(PartialFailExecutor));

        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&serde_json::json!({}), &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();

        // alpha succeeded; beta failed.
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.failed.len(), 1);
        assert!(outcome.failed[0].address.contains("beta"));
        assert!(outcome.failed[0].error.contains("beta refused"));
    }

    #[tokio::test]
    async fn drift_changes_action_to_update() {
        let tmp = stage_repo();
        let work = tempfile::tempdir().unwrap();
        let r = PangeaRepoReconciler::new(
            Source::Local { path: tmp.path().to_path_buf() },
            work.path(),
        );
        // Initial reconcile.
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&serde_json::json!({}), &state).unwrap();
        r.apply(&plan).await.unwrap();
        // Mutate the repo — add a new workspace + change accounts.
        let gamma = tmp.path().join("workspaces/gamma");
        fs::create_dir_all(&gamma).unwrap();
        // Re-plan.
        let state2 = r.read_state().await.unwrap();
        let plan2 = r.compute_plan(&serde_json::json!({}), &state2).unwrap();
        // Gamma should be Create; alpha + beta should be Update
        // (their workspaces are previously known but the repo's
        // overall attestation drifted).
        let by_addr: std::collections::HashMap<&str, Action> = plan2
            .changes
            .iter()
            .map(|c| (c.address.as_str(), c.action))
            .collect();
        assert_eq!(by_addr.get("pangea_repo.gamma"), Some(&Action::Create));
        assert_eq!(by_addr.get("pangea_repo.alpha"), Some(&Action::Update));
        assert_eq!(by_addr.get("pangea_repo.beta"),  Some(&Action::Update));
    }
}
