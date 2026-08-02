//! `TerraformReconciler` — wraps the existing magma-plan + magma-apply
//! pipeline as a Reconciler trait impl. Proves that the typed
//! convergence substrate is a strict generalization of magma's
//! terraform-shaped state path: nothing about the existing magma
//! pipeline is bypassed.
//!
//! The `read_state` / `apply` calls delegate to a magma `Backend`
//! impl. The `compute_plan` call delegates to `magma_plan::plan`.
//! Plans + Outcomes are re-shaped into the universal types for
//! cross-reconciler composition.
//!
//! For M0.x this impl is structurally complete but not yet wired
//! into pangea-operator's controller routing — that's M0.13. The
//! tests below exercise the conversion logic against an in-memory
//! backend.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use crate::{
    Action, AppliedChange, FailedChange, Outcome, Plan, Reconciler, ReconcilerError, build_outcome,
    change,
};

/// Wrap any `magma_backend::Backend` into a typed Reconciler.
pub struct TerraformReconciler<B: magma_backend::Backend + 'static> {
    backend: Arc<B>,
}

/// Map magma's typed Action (more granular: Create/Read/Update/
/// Delete/Replace/Forget/CreateThenDelete/DeleteThenCreate/NoOp)
/// into the universal Action surface. Granular variants collapse
/// to their closest universal equivalent.
fn magma_action_to_universal(a: magma_types::Action) -> Action {
    match a {
        magma_types::Action::Create => Action::Create,
        magma_types::Action::Update => Action::Update,
        magma_types::Action::Delete => Action::Delete,
        magma_types::Action::Replace => Action::Replace,
        magma_types::Action::NoOp => Action::NoOp,
        // Read is observe-only — surface as NoOp at the universal layer.
        magma_types::Action::Read => Action::NoOp,
        // Forget removes from state without touching cloud — model
        // as Delete from the universal POV.
        magma_types::Action::Forget => Action::Delete,
        // The two-step replacement variants map to Replace.
        magma_types::Action::CreateThenDelete => Action::Replace,
        magma_types::Action::DeleteThenCreate => Action::Replace,
    }
}

impl<B: magma_backend::Backend + 'static> TerraformReconciler<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl<B: magma_backend::Backend + 'static> Reconciler for TerraformReconciler<B> {
    fn kind(&self) -> &'static str {
        "terraform"
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let state = self
            .backend
            .read_state()
            .await
            .map_err(|e| ReconcilerError::ReadState(e.to_string()))?;
        serde_json::to_value(state).map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        // Build typed magma Config + State, run magma_plan, then
        // re-shape the typed Plan into the universal shape.
        let cfg = magma_config::Config::from_json(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("magma_config: {e}")))?;
        let st: magma_types::State = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state decode: {e}")))?;
        let magma_plan = magma_plan::plan(&cfg, &st)
            .map_err(|e| ReconcilerError::ComputePlan(format!("magma_plan: {e}")))?;

        let changes = magma_plan
            .resource_changes
            .iter()
            .map(|rc| {
                let action = magma_action_to_universal(rc.action);
                let address = format!("{}.{}", rc.address.type_id.0, rc.address.name);
                change(address, action, rc.before.clone(), rc.after.clone())
            })
            .collect();

        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let started_at = Utc::now();
        // Read the current state, rebuild the magma::Plan from the
        // universal Plan's changes (lossy — we don't carry the full
        // typed magma Plan through; future M0.x carries the typed
        // magma plan_id alongside as an attestation pair). For now,
        // the canonical path is: read live magma_types::State, write
        // through magma_apply::run_plan on a reconstructed magma plan.

        let mut state = self
            .backend
            .read_state()
            .await
            .map_err(|e| ReconcilerError::Apply(e.to_string()))?;

        // Rebuild magma_types::Plan from universal changes.
        let magma_changes: Vec<magma_types::ResourceChange> = plan
            .changes
            .iter()
            .filter_map(|c| {
                let action = match c.action {
                    Action::Create => magma_types::Action::Create,
                    Action::Update => magma_types::Action::Update,
                    Action::Delete => magma_types::Action::Delete,
                    Action::Replace => magma_types::Action::Replace,
                    Action::NoOp => return None,
                };
                // Address is "<type>.<name>"; split.
                let (type_id, name) = c.address.split_once('.')?;
                Some(magma_types::ResourceChange {
                    address: magma_types::ResourceAddress {
                        module: magma_types::ModulePath::root(),
                        kind: magma_types::ResourceKind::Managed,
                        type_id: magma_types::ResourceTypeId(type_id.into()),
                        name: name.into(),
                        key: None,
                    },
                    action,
                    before: c.before.clone(),
                    after: c.after.clone(),
                    reasons: vec![],
                    meta: Default::default(),
                })
            })
            .collect();
        let magma_plan = magma_types::Plan {
            id: magma_types::PlanId([0u8; 32]),
            created_at: chrono::Utc::now(),
            config_root: std::path::PathBuf::new(),
            variables: Default::default(),
            resource_changes: magma_changes,
            output_changes: vec![],
            // An apply-side reconstruction of an already-decided change
            // set — it observed nothing itself. The trust record belongs
            // to whatever produced the universal plan upstream.
            observation: magma_types::Observation::unrefreshed(),
        };

        let outcome = magma_apply::run_plan(&magma_plan, &mut state)
            .map_err(|e| ReconcilerError::Apply(e.to_string()))?;
        self.backend
            .write_state(&state)
            .await
            .map_err(|e| ReconcilerError::Apply(e.to_string()))?;

        let applied: Vec<AppliedChange> = outcome
            .applied
            .iter()
            .map(|a| AppliedChange {
                address: format!("{}.{}", a.address.type_id.0, a.address.name),
                action: magma_action_to_universal(a.action),
            })
            .collect();
        let failed: Vec<FailedChange> = outcome
            .failed
            .iter()
            .map(|f| FailedChange {
                address: format!("{}.{}", f.address.type_id.0, f.address.name),
                action: magma_action_to_universal(f.action),
                error: f.reason.clone(),
            })
            .collect();

        Ok(build_outcome(plan, applied, failed, started_at))
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_backend::{Backend as _, InMemoryBackend};

    #[tokio::test]
    async fn empty_backend_yields_empty_state() {
        let r = TerraformReconciler::new(Arc::new(InMemoryBackend::new()));
        let state = r.read_state().await.unwrap();
        let parsed: magma_types::State = serde_json::from_value(state).unwrap();
        assert_eq!(parsed.resources.len(), 0);
    }

    #[tokio::test]
    async fn plan_on_empty_state_produces_creates_for_config_resources() {
        let r = TerraformReconciler::new(Arc::new(InMemoryBackend::new()));
        let config = serde_json::json!({
            "provider": { "aws": { "region": "us-east-1" } },
            "resource": { "aws_iam_role": { "node": { "name": "node-role" } } },
        });
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert!(plan.change_count() >= 1);
        assert!(
            plan.changes
                .iter()
                .any(|c| c.address == "aws_iam_role.node")
        );
        assert_eq!(plan.changes[0].action, Action::Create);
    }

    #[tokio::test]
    async fn apply_converges_state() {
        let backend = Arc::new(InMemoryBackend::new());
        let r = TerraformReconciler::new(Arc::clone(&backend));
        let config = serde_json::json!({
            "provider": { "aws": { "region": "us-east-1" } },
            "resource": { "aws_iam_role": { "node": { "name": "x" } } },
        });
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        let state2 = backend.read_state().await.unwrap();
        assert_eq!(state2.resources.len(), 1);
    }
}
