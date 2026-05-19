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
/// describing what the repo expects vs what magma observed last.
pub struct PangeaRepoReconciler {
    pub source:   Source,
    pub work_dir: std::path::PathBuf,
}

impl PangeaRepoReconciler {
    pub fn new(source: Source, work_dir: impl Into<std::path::PathBuf>) -> Self {
        Self { source, work_dir: work_dir.into() }
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
        // M0 apply is a no-op modulo bookkeeping: we record the
        // attestation as the new last_attestation. The actual
        // per-workspace MagmaExecutor invocation lands in M2 when
        // the operator wires the executor in.
        //
        // Today, applying a plan against a fresh repo means
        // "magma observed the repo + recorded its attestation;
        // operator can now drive per-workspace reconciles using
        // discover()-returned workspace list."
        let started_at = chrono::Utc::now();
        let mut applied = vec![];
        for change in &plan.changes {
            applied.push(AppliedChange {
                address: change.address.clone(),
                action:  change.action,
            });
        }
        // Persist new state.
        let local = self.source.materialize(&self.work_dir).ok();
        if let Some(local) = local {
            if let Ok(repo) = crate::discover(local) {
                let new_state = RepoObservedState {
                    last_attestation: Some(repo.repo_attestation),
                    last_commit_sha:  None, // M3 fills this
                    workspaces:       repo
                        .workspaces
                        .iter()
                        .map(|w| (w.name.clone(), String::new()))
                        .collect(),
                };
                let state_path = self.work_dir.join("magma-repo-state.json");
                let _ = std::fs::write(
                    &state_path,
                    serde_json::to_vec_pretty(&new_state).unwrap_or_default(),
                );
            }
        }
        Ok(Outcome {
            plan_id:     plan.id.clone(),
            kind:        "pangea_repo".into(),
            applied,
            failed:      vec![],
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
