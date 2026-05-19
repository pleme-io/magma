//! magma-controller — complete operator-loop composition.
//!
//! Wraps `Reconciler` + `DriftPolicy` + `BudgetedReconciler` +
//! `PlanStream` + `LifecycleState` + `Bundle` + `Metrics` into ONE
//! reusable controller. The "I want a complete operator" composition
//! every reconciler kind plugs into.
//!
//! Calling `controller.reconcile(&config)` runs the full loop:
//!
//! 1. FSM Idle → Planning
//! 2. read_state (via budgeted reconciler)
//! 3. compute_plan + emit PlanComputed event + metrics
//! 4. classify drift against policy + emit DriftClassified event + metrics
//! 5. branch on ReconcileResult:
//!    * NoChange → FSM → Stable
//!    * Refused → FSM → Refused
//!    * HeldForApproval → FSM → Approving (caller drives further)
//!    * Applied → apply + emit ApplyOutcome event + metrics + FSM →
//!      Verifying → Stable
//! 6. build a tamper-evident magma-bundle
//! 7. return a typed ControllerOutcome carrying the bundle + final FSM state
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.5 + §IV.7.

#![deny(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use magma_budget::BudgetedReconciler;
use magma_bundle::{Bundle, BundleError};
use magma_converge::{Reconciler, ReconcilerError};
use magma_drift::{classify, reconcile_with_policy, DriftPolicy, ReconcileResult};
use magma_fsm::{LifecycleState, Phase, TransitionError};
use magma_metrics::Metrics;
use magma_stream::PlanStream;

// ── Errors ────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("reconciler: {0}")]
    Reconciler(#[from] ReconcilerError),
    #[error("fsm transition: {0}")]
    FsmTransition(#[from] TransitionError),
    #[error("bundle: {0}")]
    Bundle(#[from] BundleError),
}

// ── Typed terminal result ─────────────────────────────────────────

/// Output of one `reconcile(...)` call. Wraps the typed
/// `ReconcileResult` from magma-drift (no duplicate enum) plus the
/// FSM lifecycle snapshot and the tamper-evident Bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerOutcome {
    pub result:    ReconcileResult,
    pub bundle:    Bundle,
    pub lifecycle: LifecycleState,
}

impl ControllerOutcome {
    /// Convenience: did the reconcile reach Stable?
    pub fn fully_succeeded(&self) -> bool {
        matches!(self.result, ReconcileResult::NoChange { .. } | ReconcileResult::Applied { .. })
            && self.lifecycle.current == Phase::Stable
    }
}

// ── ReconcileController ───────────────────────────────────────────

/// The complete operator loop, parameterized by reconciler kind.
pub struct ReconcileController<R: Reconciler> {
    /// Wrapped reconciler with budget + retry built in.
    reconciler: Arc<BudgetedReconciler<R>>,
    /// Drift classification policy.
    policy:     DriftPolicy,
    /// Shared event stream (typically wired with K8sEventSink +
    /// JsonLinesSink + TracingSink by the operator).
    stream:     Arc<PlanStream>,
    /// Prometheus metrics handle (shared across kinds).
    metrics:    Arc<Metrics>,
    /// Workspace identifier (CR name + namespace, or the
    /// operator-side state-name triple).
    workspace:  String,
}

impl<R: Reconciler> ReconcileController<R> {
    pub fn new(
        reconciler: BudgetedReconciler<R>,
        policy:     DriftPolicy,
        stream:     Arc<PlanStream>,
        metrics:    Arc<Metrics>,
        workspace:  impl Into<String>,
    ) -> Self {
        Self {
            reconciler: Arc::new(reconciler),
            policy,
            stream,
            metrics,
            workspace: workspace.into(),
        }
    }

    /// Reconciler kind for this controller (echoes the inner reconciler's
    /// `kind()`).
    pub fn kind(&self) -> &'static str {
        self.reconciler.kind()
    }

    /// Run the full reconcile loop end-to-end.
    pub async fn reconcile(&self, config: &Value) -> Result<ControllerOutcome, ControllerError> {
        let mut lifecycle = LifecycleState::new();
        lifecycle.transition(Phase::Planning, None, "controller: trigger")?;

        // The composed dispatch — magma-budget owns concurrency +
        // retry; magma-drift owns classify + decide + apply.
        let result = reconcile_with_policy(&*self.reconciler, config, &self.policy).await?;

        // Universal metric + stream emission via the typed
        // ReconcileResult accessors — no per-variant branching.
        let plan_id = result.plan_id().clone();
        self.metrics.record_plan(result.plan());
        self.stream.emit_plan(self.kind(), result.plan()).await;
        if let Some(report) = result.report() {
            self.metrics.record_drift(report);
            self.stream.emit_drift(report).await;
        }
        if let Some(outcome) = result.outcome() {
            self.metrics.record_outcome(outcome);
            self.stream.emit_outcome(outcome).await;
        }

        // Drive the FSM through phases based on the typed result kind.
        let (final_phase, reason) = match &result {
            ReconcileResult::NoChange { .. } => (Phase::Stable, "no changes".into()),
            ReconcileResult::Refused { refused, .. } => {
                (Phase::Refused, format!("policy refused {refused} change(s)"))
            }
            ReconcileResult::HeldForApproval { held, .. } => {
                (Phase::Approving, format!("policy requires approval on {held} change(s)"))
            }
            ReconcileResult::Applied { .. } => {
                lifecycle.transition(Phase::Applying,  Some(plan_id.clone()), "applying")?;
                lifecycle.transition(Phase::Verifying, Some(plan_id.clone()), "applied")?;
                (Phase::Stable, "verified, no drift".into())
            }
            ReconcileResult::AppliedWithFailures { outcome, .. } => {
                lifecycle.transition(Phase::Applying,  Some(plan_id.clone()), "applying")?;
                lifecycle.transition(Phase::Verifying, Some(plan_id.clone()), "applied with failures")?;
                (Phase::Failed, format!("{} resource(s) failed apply", outcome.failed.len()))
            }
        };
        lifecycle.transition(final_phase, Some(plan_id), reason)?;

        let drift_for_bundle = match result.report() {
            Some(report) => report.clone(),
            None         => classify(result.plan(), &self.policy),
        };
        let bundle = Bundle::new(
            self.kind(),
            self.workspace.clone(),
            result.plan().clone(),
            result.outcome().cloned(),
            drift_for_bundle,
            lifecycle.clone(),
            vec![],
        )?;

        Ok(ControllerOutcome { result, bundle, lifecycle })
    }

}

/// Erased ReconcileController surface, useful when storing many
/// controllers of different kinds in one collection.
#[async_trait]
pub trait DynController: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn reconcile(&self, config: &Value) -> Result<ControllerOutcome, ControllerError>;
}

#[async_trait]
impl<R: Reconciler + 'static> DynController for ReconcileController<R> {
    fn kind(&self) -> &'static str {
        ReconcileController::kind(self)
    }
    async fn reconcile(&self, config: &Value) -> Result<ControllerOutcome, ControllerError> {
        ReconcileController::reconcile(self, config).await
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_budget::{ConcurrencyLimit, RetryPolicy};
    use magma_converge::inmemory::InMemoryKvReconciler;
    use prometheus::Registry;
    use serde_json::json;

    fn make_controller() -> (ReconcileController<InMemoryKvReconciler>, Registry) {
        let inner = InMemoryKvReconciler::new();
        let budgeted = BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(4),
            RetryPolicy::none(),
        );
        let registry = Registry::new();
        let metrics = Arc::new(Metrics::register(&registry).unwrap());
        let stream = Arc::new(PlanStream::new());
        let controller = ReconcileController::new(
            budgeted,
            DriftPolicy::conservative_default(),
            stream,
            metrics,
            "ws-1",
        );
        (controller, registry)
    }

    #[tokio::test]
    async fn no_change_path_reaches_stable() {
        let (controller, _registry) = make_controller();
        // Empty config + empty state → no plan, FSM → Stable.
        let outcome = controller.reconcile(&json!({})).await.unwrap();
        assert!(matches!(outcome.result, ReconcileResult::NoChange { .. }));
        assert_eq!(outcome.lifecycle.current, Phase::Stable);
        assert!(outcome.fully_succeeded());
    }

    #[tokio::test]
    async fn applied_path_walks_full_fsm() {
        let (controller, _registry) = make_controller();
        // Config with two creates → all Functional → AutoCorrectWithAlert → applied.
        let outcome = controller.reconcile(&json!({ "a": 1, "b": 2 })).await.unwrap();
        match &outcome.result {
            ReconcileResult::Applied { outcome: o, plan, .. } => {
                assert!(o.fully_succeeded());
                assert_eq!(o.applied.len(), 2);
                // Plan now carries the full change set.
                assert_eq!(plan.change_count(), 2);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(outcome.lifecycle.current, Phase::Stable);
        assert_eq!(outcome.lifecycle.len(), 4);
        let phases: Vec<Phase> = outcome.lifecycle.history.iter().map(|t| t.to).collect();
        assert_eq!(phases, vec![Phase::Planning, Phase::Applying, Phase::Verifying, Phase::Stable]);
        // Bundle carries the full plan, not the empty-changes hack.
        assert_eq!(outcome.bundle.change_count(), 2);
    }

    #[tokio::test]
    async fn held_for_approval_path_stops_at_approving() {
        // Pre-seed state with a key whose Delete (Critical) needs approval.
        let inner = InMemoryKvReconciler::with_state(
            [("doomed".to_string(), json!("x"))].into_iter().collect(),
        );
        let budgeted = BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(1),
            RetryPolicy::none(),
        );
        let registry = Registry::new();
        let metrics = Arc::new(Metrics::register(&registry).unwrap());
        let stream = Arc::new(PlanStream::new());
        let controller = ReconcileController::new(
            budgeted,
            DriftPolicy::conservative_default(),
            stream,
            metrics,
            "ws-held",
        );

        let outcome = controller.reconcile(&json!({})).await.unwrap();
        match &outcome.result {
            ReconcileResult::HeldForApproval { held, plan, .. } => {
                assert_eq!(*held, 1);
                assert_eq!(plan.change_count(), 1);
            }
            other => panic!("expected HeldForApproval, got {other:?}"),
        }
        assert_eq!(outcome.lifecycle.current, Phase::Approving);
        assert!(!outcome.fully_succeeded());
    }

    #[tokio::test]
    async fn refused_path_stops_at_refused() {
        let inner = InMemoryKvReconciler::new();
        let budgeted = BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(1),
            RetryPolicy::none(),
        );
        let registry = Registry::new();
        let metrics = Arc::new(Metrics::register(&registry).unwrap());
        let stream = Arc::new(PlanStream::new());
        // Refuse-everything policy.
        let policy = DriftPolicy {
            rules: vec![magma_drift::PolicyRule {
                name:           "refuse-all".into(),
                severity:       None,
                action:         None,
                address_prefix: None,
                decision:       magma_drift::DriftDecision::Refuse,
            }],
            fallback: magma_drift::DriftDecision::Refuse,
        };
        let controller = ReconcileController::new(budgeted, policy, stream, metrics, "ws-refuse");

        let outcome = controller.reconcile(&json!({ "x": 1 })).await.unwrap();
        match &outcome.result {
            ReconcileResult::Refused { refused, plan, .. } => {
                assert_eq!(*refused, 1);
                assert_eq!(plan.change_count(), 1);
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert_eq!(outcome.lifecycle.current, Phase::Refused);
    }

    #[tokio::test]
    async fn metrics_recorded_during_reconcile() {
        let (controller, registry) = make_controller();
        controller.reconcile(&json!({ "a": 1 })).await.unwrap();

        let encoder = prometheus::TextEncoder::new();
        let mfs = registry.gather();
        let mut buf = vec![];
        prometheus::Encoder::encode(&encoder, &mfs, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains(r#"magma_plan_computed_total{kind="inmemory_kv"} 1"#));
        assert!(text.contains(r#"magma_apply_outcome_total{kind="inmemory_kv",result="applied"} 1"#));
    }

    #[tokio::test]
    async fn dyn_controller_dispatch_works() {
        let (controller, _registry) = make_controller();
        let dyn_c: Arc<dyn DynController> = Arc::new(controller);
        assert_eq!(dyn_c.kind(), "inmemory_kv");
        let outcome = dyn_c.reconcile(&json!({ "y": 7 })).await.unwrap();
        assert!(outcome.fully_succeeded());
    }
}
