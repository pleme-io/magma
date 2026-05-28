//! magma-converge — universal state-convergence substrate.
//!
//! One typed `Reconciler` trait that fits any declarative API.
//! Terraform/OpenTofu is one shape. Kubernetes is another. The same
//! diff-then-apply pattern lives behind dozens of APIs we already
//! touch: GitHub, DNS, Helm, Slack, PagerDuty, Datadog, Grafana,
//! Linear, Stripe, Vault, Auth0, …
//!
//! Every reconciler obeys the same trait laws (see `tests/laws`).
//! Every reconciler shares typed `Plan` / `Outcome` / `Change`
//! shapes so downstream consumers (drift classification,
//! attestation, K8s events) don't care which kind produced them.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md`.

#![deny(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub mod dns;
pub mod engine;
pub mod apply;
pub mod artifact;
pub mod backend_error;
pub mod blobstore;
pub mod condition;
pub mod decision;
pub mod drift;
pub mod github;
pub mod health;
pub mod helm;
pub mod inmemory;
pub mod inventory;
pub mod manifest;
pub mod meta;
pub mod outcome;
pub mod policy;
pub mod refspec;
pub mod selector;
pub mod terraform;
pub mod vault;
pub mod webhook;

pub use apply::{ApplyCounts, ApplyDiff, ApplyOutcome, ApplyReport, ApplyStatus};
pub use outcome::{best_of, worst_of, OutcomeLattice};
pub use artifact::{Artifact, ArtifactDigest, DigestAlgo, DigestError, Provenance};
pub use backend_error::BackendError;
pub use blobstore::{BlobMetadata, BlobStoreBackend, BlobStoreError, InMemoryBlobStore};
pub use condition::{Condition, ConditionSet, ConditionStatus};
pub use decision::Decision;
pub use drift::DriftPolicy;
pub use engine::ConvergeEngine;
pub use health::{
    AlwaysReady, ChainedHealthCheck, ClosureCheck, HealthCheck, HealthCounts, HealthReport,
    NeverReady, ReadyState,
};
pub use inventory::{Inventory, InventoryDiff, ResourceRef};
pub use manifest::{Manifest, TypeMeta};
pub use meta::{ObjectMeta, OwnerReference};
pub use policy::CascadePolicy;
pub use refspec::{RefSpec, RefSpecParseError};
pub use selector::{LabelSelector, LabelSelectorOperator, LabelSelectorRequirement};
pub use webhook::{
    HeaderTokenValidator, NoOpValidator, WebhookError, WebhookEvent, WebhookKind,
    WebhookRequest, WebhookValidator,
};

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ReconcilerError {
    #[error("read state: {0}")]
    ReadState(String),
    #[error("compute plan: {0}")]
    ComputePlan(String),
    #[error("apply: {0}")]
    Apply(String),
    #[error("validation: {0}")]
    Validation(String),
    #[error("transient: {0}")]
    Transient(String),
    #[error("other: {0}")]
    Other(String),
}

// ── Universal Plan + Change types ──────────────────────────────────

/// A typed plan_id is BLAKE3 of the canonical plan-body bytes.
/// Deterministic — same `(config, state, reconciler kind)` produce
/// equal plan_ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub String);

impl PlanId {
    /// Compute a plan id from canonical bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(blake3::hash(bytes).as_bytes()))
    }
}

/// What kind of operation a `Change` represents. The five shapes
/// every reconciler emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Update,
    Delete,
    Replace,
    NoOp,
}

/// Severity classification — used by `magma-drift` to decide
/// auto-correct vs alert vs require-approval. Reconciler impls set
/// reasonable defaults; downstream policy can override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSeverity {
    /// Tags, labels, descriptions — usually safe to auto-fix.
    Cosmetic,
    /// Behavior-altering but not security-relevant.
    Functional,
    /// Security/availability-relevant — IAM, SG rules, encryption,
    /// data loss vectors. Default to require-approval.
    Critical,
}

/// One typed resource-level change inside a `Plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Resource address — kind-specific (e.g. `aws_vpc.net`,
    /// `github_repo.foo`, `dns_record.bar`).
    pub address: String,
    /// Action this change represents.
    pub action: Action,
    /// Severity for drift-policy routing.
    pub severity: ChangeSeverity,
    /// Pre-state JSON (None for Create).
    pub before: Option<Value>,
    /// Post-state JSON (None for Delete).
    pub after: Option<Value>,
}

/// A typed Plan — universal across reconciler kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// BLAKE3-derived plan id; deterministic for `(config, state, kind)`.
    pub id: PlanId,
    /// The kind that produced this plan ("terraform", "github", …).
    pub kind: String,
    /// When the plan was computed. NOT included in plan_id derivation.
    pub created_at: DateTime<Utc>,
    /// The typed changes the plan would apply.
    pub changes: Vec<Change>,
}

impl Plan {
    /// Compute a plan id from changes + kind. Deterministic;
    /// `created_at` is not part of the hash so two plans computed
    /// at different times against identical (config, state) are
    /// id-equal.
    pub fn derive_id(kind: &str, changes: &[Change]) -> PlanId {
        // Serialize a canonical projection: kind + each change as
        // (address, action, severity, before, after). Avoids
        // serializing `created_at` or anything else that varies.
        let projection: Vec<Value> = changes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "address":  c.address,
                    "action":   c.action,
                    "severity": c.severity,
                    "before":   c.before,
                    "after":    c.after,
                })
            })
            .collect();
        let canonical = serde_json::json!({ "kind": kind, "changes": projection });
        PlanId::of(
            serde_json::to_vec(&canonical)
                .unwrap_or_default()
                .as_slice(),
        )
    }

    /// Build a Plan with `derive_id`-computed id + `Utc::now`.
    pub fn new(kind: impl Into<String>, changes: Vec<Change>) -> Self {
        let kind = kind.into();
        let id = Self::derive_id(&kind, &changes);
        Self {
            id,
            kind,
            created_at: Utc::now(),
            changes,
        }
    }

    /// True iff the plan has no Create/Update/Delete/Replace changes.
    pub fn is_noop(&self) -> bool {
        self.changes
            .iter()
            .all(|c| matches!(c.action, Action::NoOp))
    }

    /// Number of non-noop changes.
    pub fn change_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| !matches!(c.action, Action::NoOp))
            .count()
    }
}

/// One `apply` step's record — what landed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedChange {
    pub address: String,
    pub action: Action,
}

/// One `apply` step's failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedChange {
    pub address: String,
    pub action: Action,
    pub error: String,
}

/// Universal apply Outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub plan_id: PlanId,
    pub kind: String,
    pub applied: Vec<AppliedChange>,
    pub failed: Vec<FailedChange>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

impl Outcome {
    pub fn fully_succeeded(&self) -> bool {
        self.failed.is_empty()
    }
}

// ── The Reconciler trait ──────────────────────────────────────────

/// The universal reconciler trait. Any declarative API can implement
/// this; the engine routes typed `(config, kind)` pairs to the right
/// reconciler.
///
/// # Laws (every impl must obey)
///
/// 1. **`read_state` is referentially transparent** modulo external
///    change.
/// 2. **`compute_plan` is deterministic.** Same `(config, state)` →
///    equal `Plan` (modulo `created_at`) and equal `plan_id`.
/// 3. **Empty plans are no-ops.** `apply(noop_plan)` doesn't mutate
///    observable state.
/// 4. **Apply converges.** After `apply(plan)`, the next
///    `detect_drift(config)` produces an empty Plan (assuming no
///    external mutation).
#[async_trait]
pub trait Reconciler: Send + Sync {
    /// Stable kind name. Used by the engine for routing and by
    /// downstream consumers (drift, attestation) to label events.
    fn kind(&self) -> &'static str;

    /// Read current observed state.
    async fn read_state(&self) -> Result<Value, ReconcilerError>;

    /// Compute the typed plan. Pure function — no I/O. Determinism
    /// is a trait law.
    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError>;

    /// Apply a typed plan. Returns a typed Outcome.
    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError>;

    /// Convenience: drift detection = compute_plan(config, read_state()).
    async fn detect_drift(&self, config: &Value) -> Result<Plan, ReconcilerError> {
        let state = self.read_state().await?;
        self.compute_plan(config, &state)
    }
}

/// Type-erased Arc<dyn Reconciler> for engine storage.
pub type SharedReconciler = Arc<dyn Reconciler>;

// ── ApplyMetrics — instrumentation seam ────────────────────────────

/// Lightweight metrics hook that wrappers (e.g. `BudgetedReconciler`)
/// call at apply boundaries. magma-converge stays free of Prometheus
/// / metrics-rs / OpenTelemetry — implementors plug in whatever they
/// want. `magma-metrics::Metrics` is the canonical Prometheus impl.
///
/// Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.3.
pub trait ApplyMetrics: Send + Sync {
    /// Called when a reconciler-driven `apply` begins. Implementors
    /// typically increment an `in_flight` gauge.
    fn apply_started(&self, kind: &str);

    /// Called when an apply finishes (success OR failure).
    /// Implementors typically decrement the same gauge.
    fn apply_finished(&self, kind: &str);
}

/// No-op implementation — useful when callers don't want
/// instrumentation. `Arc::new(NoMetrics)` satisfies the trait
/// without any side effects.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMetrics;

impl ApplyMetrics for NoMetrics {
    fn apply_started(&self, _kind: &str) {}
    fn apply_finished(&self, _kind: &str) {}
}

// ── Convenience helpers ───────────────────────────────────────────

/// Build an `Outcome` shape matching the plan_id + kind, with the
/// given applied + failed lists.
pub fn build_outcome(
    plan: &Plan,
    applied: Vec<AppliedChange>,
    failed: Vec<FailedChange>,
    started_at: DateTime<Utc>,
) -> Outcome {
    Outcome {
        plan_id: plan.id.clone(),
        kind: plan.kind.clone(),
        applied,
        failed,
        started_at,
        finished_at: Utc::now(),
    }
}

/// Build a `Change` with a sensible default severity inferred from
/// the action. Reconcilers can override per-resource.
pub fn change(
    address: impl Into<String>,
    action: Action,
    before: Option<Value>,
    after: Option<Value>,
) -> Change {
    let severity = match action {
        Action::Create => ChangeSeverity::Functional,
        Action::Update => ChangeSeverity::Functional,
        Action::Delete => ChangeSeverity::Critical,
        Action::Replace => ChangeSeverity::Critical,
        Action::NoOp => ChangeSeverity::Cosmetic,
    };
    Change {
        address: address.into(),
        action,
        severity,
        before,
        after,
    }
}

/// Build a `Change` with explicit severity.
pub fn change_with_severity(
    address: impl Into<String>,
    action: Action,
    severity: ChangeSeverity,
    before: Option<Value>,
    after: Option<Value>,
) -> Change {
    Change {
        address: address.into(),
        action,
        severity,
        before,
        after,
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod core_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plan_id_is_deterministic() {
        let changes = vec![
            change("a", Action::Create, None, Some(json!({"k": 1}))),
            change(
                "b",
                Action::Update,
                Some(json!({"v": 1})),
                Some(json!({"v": 2})),
            ),
        ];
        let id1 = Plan::derive_id("test", &changes);
        let id2 = Plan::derive_id("test", &changes);
        assert_eq!(id1, id2);
        // Length is hex-encoded BLAKE3 (32 bytes → 64 hex chars).
        assert_eq!(id1.0.len(), 64);
    }

    #[test]
    fn plan_id_changes_with_kind() {
        let changes = vec![change("a", Action::Create, None, Some(json!({})))];
        let id_terraform = Plan::derive_id("terraform", &changes);
        let id_github = Plan::derive_id("github", &changes);
        assert_ne!(id_terraform, id_github);
    }

    #[test]
    fn plan_id_changes_with_changes() {
        let id1 = Plan::derive_id("k", &[change("a", Action::Create, None, Some(json!({})))]);
        let id2 = Plan::derive_id("k", &[change("a", Action::Delete, Some(json!({})), None)]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn plan_id_is_independent_of_created_at() {
        let changes = vec![change("a", Action::Create, None, Some(json!({})))];
        let p1 = Plan::new("k", changes.clone());
        // Force a tiny delay so created_at differs.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let p2 = Plan::new("k", changes);
        assert_eq!(p1.id, p2.id);
        assert_ne!(p1.created_at, p2.created_at);
    }

    #[test]
    fn is_noop_handles_mixed_changes() {
        let noop_plan = Plan::new("k", vec![change("a", Action::NoOp, None, None)]);
        assert!(noop_plan.is_noop());
        let mixed = Plan::new(
            "k",
            vec![
                change("a", Action::NoOp, None, None),
                change("b", Action::Create, None, Some(json!({}))),
            ],
        );
        assert!(!mixed.is_noop());
        let empty = Plan::new("k", vec![]);
        assert!(empty.is_noop());
    }

    #[test]
    fn change_count_excludes_noops() {
        let plan = Plan::new(
            "k",
            vec![
                change("a", Action::Create, None, Some(json!({}))),
                change("b", Action::NoOp, None, None),
                change("c", Action::Update, Some(json!({})), Some(json!({}))),
            ],
        );
        assert_eq!(plan.change_count(), 2);
    }

    #[test]
    fn default_severity_inference() {
        assert_eq!(
            change("x", Action::Create, None, Some(json!({}))).severity,
            ChangeSeverity::Functional
        );
        assert_eq!(
            change("x", Action::Update, Some(json!({})), Some(json!({}))).severity,
            ChangeSeverity::Functional
        );
        assert_eq!(
            change("x", Action::Delete, Some(json!({})), None).severity,
            ChangeSeverity::Critical
        );
        assert_eq!(
            change("x", Action::Replace, Some(json!({})), Some(json!({}))).severity,
            ChangeSeverity::Critical
        );
        assert_eq!(
            change("x", Action::NoOp, None, None).severity,
            ChangeSeverity::Cosmetic
        );
    }
}
