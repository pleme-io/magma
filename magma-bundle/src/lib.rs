//! magma-bundle — compliance-ready reconcile artifact.
//!
//! Every reconcile produces typed artifacts: a `Plan` (what was
//! intended), an `Outcome` (what landed), a `DriftReport` (how
//! policy classified each change), a `LifecycleState` (which phases
//! it went through), an audit chain (every event with BLAKE3
//! linkage). This crate combines them into one `Bundle` with a
//! BLAKE3 bundle_id over the canonical serialization.
//!
//! Useful for:
//!
//! * **Compliance audits** — one tamper-evident artifact per
//!   reconcile.
//! * **Operator support** — "send us the bundle for this CR" and
//!   the bundle has everything.
//! * **Disaster recovery** — bundle pins what happened; replay
//!   verifies pre/post state.
//! * **Cross-team handoffs** — typed shape, no missing pieces.

#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use magma_converge::{Outcome, Plan, PlanId};
use magma_drift::DriftReport;
use magma_fsm::LifecycleState;
use magma_stream::Event;

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("bundle id mismatch: have {have:?}, recomputed {recomputed:?}")]
    IdMismatch { have: String, recomputed: String },
    #[error("missing required field: {0}")]
    Missing(&'static str),
}

/// Compliance-ready bundle. Carries every typed artifact a single
/// reconcile produces, plus a BLAKE3 `bundle_id` over the canonical
/// projection. Round-trips through serde + verifies via
/// `Bundle::verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// BLAKE3 hash over the canonical projection (every field
    /// except `bundle_id` itself + `built_at`).
    pub bundle_id:   String,
    /// When the bundle was built (NOT in the hash so two bundles
    /// over the same reconcile data hash equally).
    pub built_at:    DateTime<Utc>,
    /// Reconciler kind that produced this reconcile.
    pub kind:        String,
    /// Workspace identifier (CR name + namespace, or operator-side
    /// state-name triple).
    pub workspace:   String,
    /// The typed Plan.
    pub plan:        Plan,
    /// The Outcome of applying the Plan (may be a no-op outcome
    /// if the plan never applied — e.g. HeldForApproval).
    pub outcome:     Option<Outcome>,
    /// Drift classification report.
    pub drift:       DriftReport,
    /// FSM lifecycle snapshot at bundle-build time.
    pub lifecycle:   LifecycleState,
    /// Audit events (typically the magma-stream chain for this
    /// reconcile). May be empty if no stream was wired.
    pub audit:       Vec<Event>,
}

impl Bundle {
    /// Construct a Bundle. Computes `bundle_id` from the canonical
    /// projection of every field except `bundle_id` + `built_at`.
    pub fn new(
        kind:      impl Into<String>,
        workspace: impl Into<String>,
        plan:      Plan,
        outcome:   Option<Outcome>,
        drift:     DriftReport,
        lifecycle: LifecycleState,
        audit:     Vec<Event>,
    ) -> Result<Self, BundleError> {
        let kind = kind.into();
        let workspace = workspace.into();
        let bundle_id = Self::derive_id(
            &kind, &workspace, &plan, &outcome, &drift, &lifecycle, &audit,
        )?;
        Ok(Self {
            bundle_id,
            built_at: Utc::now(),
            kind,
            workspace,
            plan,
            outcome,
            drift,
            lifecycle,
            audit,
        })
    }

    /// Re-derive `bundle_id` from the canonical projection.
    pub fn derive_id(
        kind:      &str,
        workspace: &str,
        plan:      &Plan,
        outcome:   &Option<Outcome>,
        drift:     &DriftReport,
        lifecycle: &LifecycleState,
        audit:     &[Event],
    ) -> Result<String, BundleError> {
        // Plan and Outcome carry timestamps that vary across runs.
        // We project the plan via its (stable) id + canonical
        // change shape, NOT the chrono `created_at`. Same for
        // Outcome (use plan_id + applied/failed counts).
        let canonical = serde_json::json!({
            "kind":      kind,
            "workspace": workspace,
            "plan_id":   plan.id,
            "plan_changes": plan.changes,
            "outcome":   outcome.as_ref().map(|o| serde_json::json!({
                "plan_id": o.plan_id,
                "applied": o.applied,
                "failed":  o.failed,
            })),
            "drift": serde_json::json!({
                "plan_id":  drift.plan_id,
                "summary":  drift.summary,
                "events":   drift.events.iter().map(|e| serde_json::json!({
                    "kind":        e.kind,
                    "address":     e.address,
                    "action":      e.action,
                    "severity":    e.severity,
                    "decision":    e.decision,
                    "fingerprint": e.fingerprint,
                })).collect::<Vec<_>>(),
            }),
            "lifecycle": serde_json::json!({
                "current": lifecycle.current,
                "history": lifecycle.history.iter().map(|t| serde_json::json!({
                    "from":    t.from,
                    "to":      t.to,
                    "plan_id": t.plan_id,
                    "reason":  t.reason,
                })).collect::<Vec<_>>(),
            }),
            "audit": audit.iter().map(|e| serde_json::json!({
                "seq":       e.seq,
                "payload":   e.payload,
                "prev_hash": e.prev_hash,
                "hash":      e.hash,
            })).collect::<Vec<_>>(),
        });
        let bytes = serde_json::to_vec(&canonical)?;
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Verify the bundle's stored `bundle_id` matches a freshly-
    /// computed one. Use after deserialization to catch tampering.
    pub fn verify(&self) -> Result<(), BundleError> {
        let recomputed = Self::derive_id(
            &self.kind,
            &self.workspace,
            &self.plan,
            &self.outcome,
            &self.drift,
            &self.lifecycle,
            &self.audit,
        )?;
        if recomputed != self.bundle_id {
            return Err(BundleError::IdMismatch {
                have:       self.bundle_id.clone(),
                recomputed,
            });
        }
        Ok(())
    }

    /// The plan_id the bundle is keyed at (convenience accessor).
    pub fn plan_id(&self) -> &PlanId {
        &self.plan.id
    }

    /// Convenience: how many changes the bundle's plan carried.
    pub fn change_count(&self) -> usize {
        self.plan.change_count()
    }

    /// True iff the bundle reflects a successful end-to-end apply.
    pub fn fully_succeeded(&self) -> bool {
        match &self.outcome {
            Some(o) => o.fully_succeeded() && self.lifecycle.current == magma_fsm::Phase::Stable,
            None    => false,
        }
    }

    /// Serialize to a single JSON value. Suitable for storage in
    /// any blob store (S3, Postgres jsonb, K8s ConfigMap).
    pub fn to_json(&self) -> Result<serde_json::Value, BundleError> {
        Ok(serde_json::to_value(self)?)
    }

    /// Deserialize + verify. The "import this bundle" path.
    pub fn from_json_verified(value: serde_json::Value) -> Result<Self, BundleError> {
        let bundle: Bundle = serde_json::from_value(value)?;
        bundle.verify()?;
        Ok(bundle)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::{change, Action, ChangeSeverity, Outcome};
    use magma_drift::{classify, DriftPolicy};
    use magma_fsm::{LifecycleState, Phase};
    use magma_stream::{Event, EventPayload};
    use serde_json::json;

    fn sample_plan() -> Plan {
        Plan::new("terraform", vec![
            change("aws_vpc.net", Action::Create, None, Some(json!({"cidr": "10.0.0.0/16"}))),
        ])
    }

    fn sample_outcome(plan: &Plan) -> Outcome {
        Outcome {
            plan_id:     plan.id.clone(),
            kind:        plan.kind.clone(),
            applied:     vec![magma_converge::AppliedChange {
                address: "aws_vpc.net".into(),
                action:  Action::Create,
            }],
            failed:      vec![],
            started_at:  Utc::now(),
            finished_at: Utc::now(),
        }
    }

    fn sample_lifecycle(plan_id: &PlanId) -> LifecycleState {
        let mut l = LifecycleState::new();
        l.transition(Phase::Planning, Some(plan_id.clone()), "trigger").unwrap();
        l.transition(Phase::Applying, Some(plan_id.clone()), "auto").unwrap();
        l.transition(Phase::Verifying, Some(plan_id.clone()), "applied").unwrap();
        l.transition(Phase::Stable, Some(plan_id.clone()), "verified").unwrap();
        l
    }

    fn sample_audit() -> Vec<Event> {
        // Two events with a valid hash chain (built directly).
        let e0 = Event::new(
            0,
            EventPayload::Custom { category: "test".into(), message: "a".into() },
            "0".repeat(64),
        );
        let e1 = Event::new(
            1,
            EventPayload::Custom { category: "test".into(), message: "b".into() },
            e0.hash.clone(),
        );
        vec![e0, e1]
    }

    #[test]
    fn build_and_verify_round_trip() {
        let plan = sample_plan();
        let outcome = sample_outcome(&plan);
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let audit = sample_audit();

        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, audit,
        ).unwrap();
        // bundle_id is 64-char hex.
        assert_eq!(bundle.bundle_id.len(), 64);
        // Verify passes immediately.
        bundle.verify().unwrap();
    }

    #[test]
    fn bundle_id_deterministic_across_calls() {
        // Two bundles built from the same artifacts (different
        // built_at timestamps) hash equally.
        let plan = sample_plan();
        let outcome = sample_outcome(&plan);
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let audit = sample_audit();

        let id1 = Bundle::derive_id(
            "terraform", "ws-1",
            &plan, &Some(outcome.clone()), &drift, &lifecycle, &audit,
        ).unwrap();
        let id2 = Bundle::derive_id(
            "terraform", "ws-1",
            &plan, &Some(outcome), &drift, &lifecycle, &audit,
        ).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn json_round_trip_verified() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let audit = sample_audit();
        let outcome = sample_outcome(&plan);
        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, audit,
        ).unwrap();

        let json_value = bundle.to_json().unwrap();
        let restored = Bundle::from_json_verified(json_value).unwrap();
        assert_eq!(restored.bundle_id, bundle.bundle_id);
        assert_eq!(restored.workspace, "ws-1");
    }

    #[test]
    fn tampered_workspace_fails_verify() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let audit = sample_audit();
        let outcome = sample_outcome(&plan);
        let mut bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, audit,
        ).unwrap();
        // Tamper with the workspace after build.
        bundle.workspace = "ws-evil".into();
        match bundle.verify() {
            Err(BundleError::IdMismatch { .. }) => {}
            other => panic!("expected IdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn fully_succeeded_requires_stable_and_no_apply_failures() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id); // Stable
        let outcome = sample_outcome(&plan);
        let audit = sample_audit();
        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, audit,
        ).unwrap();
        assert!(bundle.fully_succeeded());
    }

    #[test]
    fn not_fully_succeeded_when_lifecycle_not_stable() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let mut lifecycle = LifecycleState::new();
        lifecycle.transition(Phase::Planning, Some(plan.id.clone()), "x").unwrap();
        // Stops at Planning — not Stable.
        let outcome = sample_outcome(&plan);
        let audit = sample_audit();
        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, audit,
        ).unwrap();
        assert!(!bundle.fully_succeeded());
    }

    #[test]
    fn not_fully_succeeded_when_no_outcome() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let audit = sample_audit();
        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, None, drift, lifecycle, audit,
        ).unwrap();
        assert!(!bundle.fully_succeeded());
    }

    #[test]
    fn empty_audit_still_bundles() {
        let plan = sample_plan();
        let drift = classify(&plan, &DriftPolicy::conservative_default());
        let lifecycle = sample_lifecycle(&plan.id);
        let outcome = sample_outcome(&plan);
        let bundle = Bundle::new(
            "terraform", "ws-1",
            plan, Some(outcome), drift, lifecycle, vec![],
        ).unwrap();
        bundle.verify().unwrap();
    }
}
