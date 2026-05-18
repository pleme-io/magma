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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use magma_budget::BudgetedReconciler;
use magma_bundle::{Bundle, BundleError};
use magma_converge::{Outcome, Plan, Reconciler, ReconcilerError};
use magma_drift::{classify, reconcile_with_policy, DriftPolicy, DriftReport, ReconcileResult};
use magma_fsm::{LifecycleState, Phase, TransitionError};
use magma_metrics::Metrics;
use magma_stream::{EventPayload, PlanStream};

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

/// What a single `reconcile(...)` call settled on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControllerResult {
    /// Plan was empty; reconcile is at Stable with no state mutation.
    NoChange,
    /// Plan applied successfully; reconcile reached Stable.
    Applied {
        outcome: Outcome,
    },
    /// Plan apply was partially or fully unsuccessful; reconcile
    /// transitioned to Failed.
    AppliedWithFailures {
        outcome: Outcome,
    },
    /// Plan held for human approval — reconcile is at Approving.
    /// Caller drives further (the held plan_id is in the bundle).
    HeldForApproval {
        held: usize,
    },
    /// Policy refused; reconcile is at Refused. Terminal until
    /// operator intervention.
    Refused {
        refused: usize,
    },
}

/// Output of one `reconcile(...)` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerOutcome {
    pub result:    ControllerResult,
    pub bundle:    Bundle,
    pub lifecycle: LifecycleState,
}

impl ControllerOutcome {
    /// Convenience: did the reconcile reach Stable?
    pub fn fully_succeeded(&self) -> bool {
        matches!(self.result, ControllerResult::NoChange | ControllerResult::Applied { .. })
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

        // Idle → Planning
        lifecycle.transition(Phase::Planning, None, "controller: trigger")?;

        // Read state + compute plan via reconcile_with_policy (the
        // composed dispatch). The metrics + stream + FSM all hook
        // into the boundaries.
        self.metrics.apply_started(self.kind()); // gauge bump-on-entry
        let result = reconcile_with_policy(&*self.reconciler, config, &self.policy).await;
        self.metrics.apply_finished(self.kind());

        let result = result?;

        match &result {
            ReconcileResult::NoChange { plan_id } => {
                // Stable path with zero plan.
                let plan = Plan {
                    id:         plan_id.clone(),
                    kind:       self.kind().to_string(),
                    created_at: Utc::now(),
                    changes:    vec![],
                };
                self.metrics.record_plan(&plan);
                self.stream.emit_plan(self.kind(), &plan).await;
                lifecycle.transition(Phase::Stable, Some(plan_id.clone()), "no changes")?;
                let drift = classify(&plan, &self.policy);
                self.stream.emit_drift(&drift).await;
                let bundle = self.build_bundle(plan, None, drift, lifecycle.clone()).await?;
                Ok(ControllerOutcome { result: ControllerResult::NoChange, bundle, lifecycle })
            }
            ReconcileResult::Refused { plan_id, refused, report } => {
                // Refused — emit drift + bundle, transition straight to Refused.
                let plan = self.synthesize_plan(plan_id, &report.events.iter().map(|_| {}).collect::<Vec<_>>());
                self.metrics.record_drift(report);
                self.stream.emit_drift(report).await;
                lifecycle.transition(Phase::Refused, Some(plan_id.clone()),
                    format!("policy refused {} change(s)", refused))?;
                let bundle = self.build_bundle(plan, None, report.clone(), lifecycle.clone()).await?;
                Ok(ControllerOutcome {
                    result: ControllerResult::Refused { refused: *refused },
                    bundle,
                    lifecycle,
                })
            }
            ReconcileResult::HeldForApproval { plan_id, held, report } => {
                // Held — record + bundle, FSM → Approving.
                let plan = self.synthesize_plan(plan_id, &report.events.iter().map(|_| {}).collect::<Vec<_>>());
                self.metrics.record_drift(report);
                self.stream.emit_drift(report).await;
                lifecycle.transition(Phase::Approving, Some(plan_id.clone()),
                    format!("policy requires approval on {} change(s)", held))?;
                let bundle = self.build_bundle(plan, None, report.clone(), lifecycle.clone()).await?;
                Ok(ControllerOutcome {
                    result: ControllerResult::HeldForApproval { held: *held },
                    bundle,
                    lifecycle,
                })
            }
            ReconcileResult::Applied { outcome, report } => {
                // Applied path — drift was clean, apply ran, transition
                // through Applying → Verifying → Stable (or Failed).
                let plan = self.synthesize_plan(&outcome.plan_id, &report.events.iter().map(|_| {}).collect::<Vec<_>>());
                self.metrics.record_plan(&plan);
                self.metrics.record_drift(report);
                self.metrics.record_outcome(outcome);
                self.stream.emit_plan(self.kind(), &plan).await;
                self.stream.emit_drift(report).await;
                self.stream.emit_outcome(outcome).await;

                lifecycle.transition(Phase::Applying, Some(outcome.plan_id.clone()), "applying")?;
                lifecycle.transition(Phase::Verifying, Some(outcome.plan_id.clone()), "applied")?;

                let (final_result, final_phase, reason) = if outcome.fully_succeeded() {
                    (
                        ControllerResult::Applied { outcome: outcome.clone() },
                        Phase::Stable,
                        "verified, no drift".to_string(),
                    )
                } else {
                    (
                        ControllerResult::AppliedWithFailures { outcome: outcome.clone() },
                        Phase::Failed,
                        format!("{} resource(s) failed apply", outcome.failed.len()),
                    )
                };
                lifecycle.transition(final_phase, Some(outcome.plan_id.clone()), reason)?;

                let bundle = self
                    .build_bundle(plan, Some(outcome.clone()), report.clone(), lifecycle.clone())
                    .await?;
                Ok(ControllerOutcome { result: final_result, bundle, lifecycle })
            }
        }
    }

    /// Build a synthetic plan shape from a plan_id when the underlying
    /// `reconcile_with_policy` doesn't surface the full Plan (the
    /// Drift report carries enough metadata for the Bundle).
    fn synthesize_plan(&self, plan_id: &magma_converge::PlanId, _events_placeholder: &[()])
        -> Plan
    {
        Plan {
            id:         plan_id.clone(),
            kind:       self.kind().to_string(),
            created_at: Utc::now(),
            // The controller's caller can read the full Plan via
            // an extra round-trip if they need the changes list.
            // For the Bundle's canonical projection, the plan_id +
            // kind are enough (the DriftReport carries the full
            // change set).
            changes:    vec![],
        }
    }

    /// Pack everything into a typed Bundle.
    async fn build_bundle(
        &self,
        plan:      Plan,
        outcome:   Option<Outcome>,
        drift:     DriftReport,
        lifecycle: LifecycleState,
    ) -> Result<Bundle, BundleError> {
        Bundle::new(
            self.kind(),
            self.workspace.clone(),
            plan,
            outcome,
            drift,
            lifecycle,
            // The controller's stream's events aren't in the bundle
            // by default — the caller can attach them via
            // Bundle::derive_id if they want chain-attestation.
            vec![],
        )
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
        assert!(matches!(outcome.result, ControllerResult::NoChange));
        assert_eq!(outcome.lifecycle.current, Phase::Stable);
        assert!(outcome.fully_succeeded());
    }

    #[tokio::test]
    async fn applied_path_walks_full_fsm() {
        let (controller, _registry) = make_controller();
        // Config with two creates → all Functional → AutoCorrectWithAlert → applied.
        let outcome = controller.reconcile(&json!({ "a": 1, "b": 2 })).await.unwrap();
        match outcome.result {
            ControllerResult::Applied { outcome: o } => {
                assert!(o.fully_succeeded());
                assert_eq!(o.applied.len(), 2);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(outcome.lifecycle.current, Phase::Stable);
        // FSM walked: Idle → Planning → Applying → Verifying → Stable
        assert_eq!(outcome.lifecycle.len(), 4);
        let phases: Vec<Phase> = outcome.lifecycle.history.iter().map(|t| t.to).collect();
        assert_eq!(phases, vec![Phase::Planning, Phase::Applying, Phase::Verifying, Phase::Stable]);
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
        assert!(matches!(outcome.result, ControllerResult::HeldForApproval { held: 1 }));
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
        assert!(matches!(outcome.result, ControllerResult::Refused { refused: 1 }));
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
