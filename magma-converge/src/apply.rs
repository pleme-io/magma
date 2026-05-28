//! Typed apply outcome — the canonical `ApplyOutcome<T>` +
//! `ApplyReport` primitives every reconciler emits after touching
//! cluster / cloud state.
//!
//! Counterpart to [`crate::Manifest<S, T>`]:
//!
//!   Manifest      = what the operator declared (typed input)
//!   ApplyOutcome  = what the reconciler did about it (typed result)
//!
//! Subsumes the "Created / Updated / Unchanged / Deleted / Skipped /
//! Failed / Conflict" classification every controller hand-rolls
//! today (FluxCD's HelmRelease history entries, Kustomization inventory
//! diff outputs, lava-operator's per-resource apply status, engenho-
//! controllers' tick-level "objects_examined / objects_changed").
//! Lifts into a typed primitive so:
//!
//! - Audit logs carry typed apply receipts (`Sink<ApplyOutcome<ResourceRef>>`)
//!   instead of free-form strings
//! - Controllers compose apply results via `ApplyReport::overall_status`
//!   for typed phase advance (mirrors `HealthReport::overall`)
//! - Per-resource diff is a typed `ApplyDiff` value the operator can
//!   reason about, not a stderr blob
//! - Conflict (SSA field-manager violation) is a first-class variant
//!   so consumers route conflict-handling separately from retryable
//!   failures
//!
//! # Composition
//!
//! ```ignore
//! let mut report = ApplyReport::new();
//! for manifest in plan.iter() {
//!     let outcome = apply_one(manifest).await;
//!     sink.record(&outcome);                                // typed audit
//!     report.push(outcome);
//! }
//! match report.overall_status() {
//!     ApplyStatus::AllSucceeded => requeue(long_interval),
//!     ApplyStatus::PartiallyFailed => requeue(short_interval),
//!     ApplyStatus::Conflict       => escalate_for_operator(),
//!     ApplyStatus::Failed         => emit_failed_event(),
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::inventory::ResourceRef;

/// Typed summary of what fields changed during an Update outcome.
/// Reconciler-specific — the granularity is up to the consumer
/// (some carry a structured diff tree, others a one-line summary).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApplyDiff {
    /// Number of fields the reconciler observed changed. Approximate;
    /// useful for metrics + change-budget audits.
    pub fields_changed: u32,
    /// Free-form human-readable diff summary. Should be short enough
    /// to fit in a K8s event message (max ~1024 chars per K8s API
    /// validation).
    pub summary: String,
}

impl ApplyDiff {
    /// Construct from a count + summary.
    pub fn new(fields_changed: u32, summary: impl Into<String>) -> Self {
        Self {
            fields_changed,
            summary: summary.into(),
        }
    }
}

/// Typed apply result. Generic over the typed payload `T` carried by
/// the success variants (commonly `ResourceRef` for apply pipelines
/// that track refs, but consumers may carry `Manifest<S>` to preserve
/// the full applied object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, magma_converge_derive::Discriminant)]
#[discriminant(method = "kind", case = "lower")]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ApplyOutcome<T> {
    /// Resource didn't exist; reconciler created it. Carries the
    /// typed payload (typically the newly-created ResourceRef or
    /// Manifest).
    Created { payload: T },

    /// Resource existed; reconciler updated it. Carries the typed
    /// payload AND a typed `ApplyDiff` summarizing what changed.
    Updated { payload: T, diff: ApplyDiff },

    /// Resource existed and was already at the declared state — no
    /// API call made. The reconciler's idempotent fast-path.
    Unchanged { payload: T },

    /// Resource was present; reconciler removed it. Doesn't carry
    /// the typed payload (it's gone) — just the ResourceRef that
    /// was removed.
    Deleted { ref_: ResourceRef },

    /// Reconciler chose not to act this cycle (e.g. dependsOn
    /// dependency not ready, suspend=true, predicate gate). Carries
    /// a typed reason for operator visibility.
    Skipped { reason: String },

    /// Apply failed. Carries reason (machine-readable, CamelCase per
    /// K8s convention) + error (free-form details). Reconciler should
    /// route per its retry policy.
    Failed { reason: String, error: String },

    /// Server-side apply conflict — another field manager owns one
    /// or more of the fields the reconciler tried to write. Carries
    /// the conflicting field-manager name(s) per K8s SSA semantics.
    /// Operator must reconcile via takeover, narrowing scope, or
    /// coordination.
    Conflict { conflict_with: String, fields: Vec<String> },
}

impl<T> ApplyOutcome<T> {
    /// `true` for outcomes that represent a successful apply step —
    /// `Created`, `Updated`, `Unchanged`, `Deleted`. (Skipped is not
    /// a failure but also not "applied".)
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            ApplyOutcome::Created { .. }
                | ApplyOutcome::Updated { .. }
                | ApplyOutcome::Unchanged { .. }
                | ApplyOutcome::Deleted { .. }
        )
    }

    /// `true` for outcomes where the reconciler hit a hard problem
    /// — `Failed` or `Conflict`. Triggers retry policy / escalation.
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            ApplyOutcome::Failed { .. } | ApplyOutcome::Conflict { .. }
        )
    }

    /// `true` for outcomes the reconciler intentionally deferred
    /// (Skipped). These should retry next cycle without escalation.
    pub fn is_skipped(&self) -> bool {
        matches!(self, ApplyOutcome::Skipped { .. })
    }

    /// `true` for outcomes that changed cluster state (`Created`,
    /// `Updated`, `Deleted`). Used by reconcilers that emit "change
    /// detected" events vs "all clean" events.
    pub fn changed_state(&self) -> bool {
        matches!(
            self,
            ApplyOutcome::Created { .. }
                | ApplyOutcome::Updated { .. }
                | ApplyOutcome::Deleted { .. }
        )
    }
}

/// Per-status count snapshot of an `ApplyReport`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyCounts {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub deleted: usize,
    pub skipped: usize,
    pub failed: usize,
    pub conflict: usize,
}

impl ApplyCounts {
    /// Total outcomes counted.
    pub fn total(&self) -> usize {
        self.created
            + self.updated
            + self.unchanged
            + self.deleted
            + self.skipped
            + self.failed
            + self.conflict
    }

    /// `created + updated + unchanged + deleted` — successful applies.
    pub fn success(&self) -> usize {
        self.created + self.updated + self.unchanged + self.deleted
    }

    /// `failed + conflict` — hard-error outcomes.
    pub fn errors(&self) -> usize {
        self.failed + self.conflict
    }

    /// `created + updated + deleted` — cluster-state-mutating applies.
    pub fn changes(&self) -> usize {
        self.created + self.updated + self.deleted
    }
}

/// Aggregate status of an `ApplyReport`. Drives controller phase
/// advance after a typed apply cycle. Mirrors the
/// `HealthReport::overall` shape (worst-severity-wins) for apply
/// outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, magma_converge_derive::Discriminant)]
#[discriminant(method = "name", case = "kebab")]
#[serde(rename_all = "kebab-case")]
pub enum ApplyStatus {
    /// Empty report or every outcome `Skipped` — nothing was attempted
    /// or accomplished. Reconciler should advance per its empty-cycle
    /// policy (often: retry, possibly with shorter interval).
    Empty,
    /// Every outcome was a success (Created/Updated/Unchanged/Deleted).
    /// Reconciler can advance to its "ready" phase.
    AllSucceeded,
    /// Some success, some skipped, no failures. Reconciler may advance
    /// or requeue depending on whether Skipped is acceptable for this
    /// cycle.
    SucceededWithSkipped,
    /// At least one Failed outcome (no Conflict). Reconciler should
    /// route per retry policy.
    Failed,
    /// At least one Conflict outcome. Conflict takes precedence over
    /// Failed because it usually requires operator intervention
    /// (takeover, narrowing scope, coordination) — never a simple
    /// retry.
    Conflict,
}

impl ApplyStatus {
    /// `true` for statuses that signal a typed-apply error
    /// (Failed | Conflict). Controllers route per retry / escalation.
    pub fn is_error(self) -> bool {
        matches!(self, ApplyStatus::Failed | ApplyStatus::Conflict)
    }
}

/// Per-outcome aggregation of an apply cycle.
///
/// Composes with [`crate::Inventory`] (one outcome per inventory ref),
/// with [`crate::Sink<ApplyOutcome<T>>`] (typed audit), and with
/// [`crate::ConditionSet`] (controllers project ApplyStatus back into
/// Reconciling/Ready conditions).
///
/// `T` defaults to `ResourceRef` — the canonical "apply touched this
/// ref" payload. Consumers that want richer payloads (full Manifest,
/// typed apply receipt) specialize the generic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApplyReport<T = ResourceRef> {
    outcomes: Vec<ApplyOutcome<T>>,
}

impl<T> ApplyReport<T> {
    /// Empty report.
    pub fn new() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    /// Append one outcome.
    pub fn push(&mut self, outcome: ApplyOutcome<T>) {
        self.outcomes.push(outcome);
    }

    /// Number of outcomes recorded.
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// Iterate recorded outcomes in insert order.
    pub fn iter(&self) -> impl Iterator<Item = &ApplyOutcome<T>> {
        self.outcomes.iter()
    }

    /// Per-kind counts.
    pub fn counts(&self) -> ApplyCounts {
        let mut c = ApplyCounts::default();
        for o in &self.outcomes {
            match o {
                ApplyOutcome::Created { .. } => c.created += 1,
                ApplyOutcome::Updated { .. } => c.updated += 1,
                ApplyOutcome::Unchanged { .. } => c.unchanged += 1,
                ApplyOutcome::Deleted { .. } => c.deleted += 1,
                ApplyOutcome::Skipped { .. } => c.skipped += 1,
                ApplyOutcome::Failed { .. } => c.failed += 1,
                ApplyOutcome::Conflict { .. } => c.conflict += 1,
            }
        }
        c
    }

    /// The aggregate status of the report:
    ///
    /// - `Empty`                — no outcomes recorded
    /// - `Conflict`             — any Conflict outcome (highest severity)
    /// - `Failed`               — any Failed outcome (no Conflict)
    /// - `SucceededWithSkipped` — some success, some skipped, no errors
    /// - `AllSucceeded`         — every outcome is success or all-empty
    ///                            after success-only filter
    pub fn overall_status(&self) -> ApplyStatus {
        if self.outcomes.is_empty() {
            return ApplyStatus::Empty;
        }
        let c = self.counts();
        if c.conflict > 0 {
            return ApplyStatus::Conflict;
        }
        if c.failed > 0 {
            return ApplyStatus::Failed;
        }
        if c.success() == 0 && c.skipped > 0 {
            // Only skips — treat as Empty (nothing applied, nothing
            // failed; reconciler should retry next cycle).
            return ApplyStatus::Empty;
        }
        if c.skipped > 0 {
            return ApplyStatus::SucceededWithSkipped;
        }
        ApplyStatus::AllSucceeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep_ref(name: &str) -> ResourceRef {
        ResourceRef::namespaced("apps", "v1", "Deployment", "ns", name)
    }

    // ── ApplyDiff ──────────────────────────────────────────────────

    #[test]
    fn apply_diff_constructor() {
        let d = ApplyDiff::new(3, "image: nginx:1.24 → 1.25, replicas: 2 → 3");
        assert_eq!(d.fields_changed, 3);
        assert!(d.summary.contains("image"));
    }

    #[test]
    fn apply_diff_serde_round_trip() {
        let d = ApplyDiff::new(2, "summary");
        let json = serde_json::to_string(&d).unwrap();
        let back: ApplyDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // ── ApplyOutcome predicates ────────────────────────────────────

    #[test]
    fn outcome_kinds_stable_discriminant() {
        assert_eq!(
            ApplyOutcome::Created { payload: dep_ref("a") }.kind(),
            "created"
        );
        assert_eq!(
            ApplyOutcome::Updated {
                payload: dep_ref("a"),
                diff: ApplyDiff::new(1, "x"),
            }
            .kind(),
            "updated"
        );
        assert_eq!(
            ApplyOutcome::Unchanged { payload: dep_ref("a") }.kind(),
            "unchanged"
        );
        assert_eq!(
            ApplyOutcome::<ResourceRef>::Deleted { ref_: dep_ref("a") }.kind(),
            "deleted"
        );
        assert_eq!(
            ApplyOutcome::<ResourceRef>::Skipped { reason: "x".into() }.kind(),
            "skipped"
        );
        assert_eq!(
            ApplyOutcome::<ResourceRef>::Failed {
                reason: "x".into(),
                error: "y".into(),
            }
            .kind(),
            "failed"
        );
        assert_eq!(
            ApplyOutcome::<ResourceRef>::Conflict {
                conflict_with: "fm".into(),
                fields: vec!["spec.replicas".into()],
            }
            .kind(),
            "conflict"
        );
    }

    #[test]
    fn outcome_is_success_classification() {
        assert!(ApplyOutcome::Created { payload: dep_ref("a") }.is_success());
        assert!(
            ApplyOutcome::Updated {
                payload: dep_ref("a"),
                diff: ApplyDiff::default(),
            }
            .is_success()
        );
        assert!(ApplyOutcome::Unchanged { payload: dep_ref("a") }.is_success());
        assert!(ApplyOutcome::<ResourceRef>::Deleted { ref_: dep_ref("a") }.is_success());

        assert!(!ApplyOutcome::<ResourceRef>::Skipped { reason: "x".into() }.is_success());
        assert!(
            !ApplyOutcome::<ResourceRef>::Failed {
                reason: "x".into(),
                error: "y".into(),
            }
            .is_success()
        );
        assert!(
            !ApplyOutcome::<ResourceRef>::Conflict {
                conflict_with: "fm".into(),
                fields: vec![],
            }
            .is_success()
        );
    }

    #[test]
    fn outcome_is_failed_classification() {
        assert!(
            ApplyOutcome::<ResourceRef>::Failed {
                reason: "x".into(),
                error: "y".into(),
            }
            .is_failed()
        );
        assert!(
            ApplyOutcome::<ResourceRef>::Conflict {
                conflict_with: "fm".into(),
                fields: vec![],
            }
            .is_failed()
        );
        assert!(!ApplyOutcome::Created { payload: dep_ref("a") }.is_failed());
        assert!(!ApplyOutcome::<ResourceRef>::Skipped { reason: "x".into() }.is_failed());
    }

    #[test]
    fn outcome_is_skipped_only_for_skipped() {
        assert!(ApplyOutcome::<ResourceRef>::Skipped { reason: "x".into() }.is_skipped());
        assert!(!ApplyOutcome::Created { payload: dep_ref("a") }.is_skipped());
        assert!(
            !ApplyOutcome::<ResourceRef>::Failed {
                reason: "x".into(),
                error: "y".into(),
            }
            .is_skipped()
        );
    }

    #[test]
    fn outcome_changed_state_distinguishes_unchanged_from_writes() {
        assert!(ApplyOutcome::Created { payload: dep_ref("a") }.changed_state());
        assert!(
            ApplyOutcome::Updated {
                payload: dep_ref("a"),
                diff: ApplyDiff::default(),
            }
            .changed_state()
        );
        assert!(ApplyOutcome::<ResourceRef>::Deleted { ref_: dep_ref("a") }.changed_state());

        assert!(
            !ApplyOutcome::Unchanged { payload: dep_ref("a") }.changed_state(),
            "Unchanged is the idempotent fast-path; no state change"
        );
        assert!(!ApplyOutcome::<ResourceRef>::Skipped { reason: "x".into() }.changed_state());
        assert!(
            !ApplyOutcome::<ResourceRef>::Failed {
                reason: "x".into(),
                error: "y".into(),
            }
            .changed_state()
        );
    }

    // ── ApplyOutcome serde ─────────────────────────────────────────

    #[test]
    fn outcome_serde_kebab_case_tags() {
        let o = ApplyOutcome::Created { payload: dep_ref("a") };
        let json = serde_json::to_string(&o).unwrap();
        // tag = "kind", value = "created" (kebab-case).
        assert!(json.contains("\"kind\":\"created\""), "got {json:?}");
        let back: ApplyOutcome<ResourceRef> = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn outcome_serde_round_trip_each_variant() {
        let cases: Vec<ApplyOutcome<ResourceRef>> = vec![
            ApplyOutcome::Created { payload: dep_ref("a") },
            ApplyOutcome::Updated {
                payload: dep_ref("b"),
                diff: ApplyDiff::new(2, "delta"),
            },
            ApplyOutcome::Unchanged { payload: dep_ref("c") },
            ApplyOutcome::Deleted { ref_: dep_ref("d") },
            ApplyOutcome::Skipped { reason: "dep-not-ready".into() },
            ApplyOutcome::Failed {
                reason: "ApplyFailed".into(),
                error: "stderr".into(),
            },
            ApplyOutcome::Conflict {
                conflict_with: "other-fm".into(),
                fields: vec!["spec.replicas".into(), "spec.image".into()],
            },
        ];

        for o in cases {
            let json = serde_json::to_string(&o).unwrap();
            let back: ApplyOutcome<ResourceRef> = serde_json::from_str(&json).unwrap();
            assert_eq!(o, back, "round-trip failed for {o:?}");
        }
    }

    // ── ApplyCounts ────────────────────────────────────────────────

    #[test]
    fn apply_counts_arithmetic() {
        let c = ApplyCounts {
            created: 1,
            updated: 2,
            unchanged: 3,
            deleted: 4,
            skipped: 5,
            failed: 6,
            conflict: 7,
        };
        assert_eq!(c.total(), 28);
        assert_eq!(c.success(), 10); // 1+2+3+4
        assert_eq!(c.errors(), 13);  // 6+7
        assert_eq!(c.changes(), 7);  // 1+2+4 (Created+Updated+Deleted)
    }

    // ── ApplyStatus + ApplyReport aggregation ──────────────────────

    #[test]
    fn report_empty_is_empty_status() {
        let r: ApplyReport = ApplyReport::new();
        assert!(r.is_empty());
        assert_eq!(r.overall_status(), ApplyStatus::Empty);
    }

    #[test]
    fn report_all_success_is_all_succeeded() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Updated {
            payload: dep_ref("b"),
            diff: ApplyDiff::default(),
        });
        r.push(ApplyOutcome::Unchanged { payload: dep_ref("c") });
        assert_eq!(r.overall_status(), ApplyStatus::AllSucceeded);
        assert!(!r.overall_status().is_error());
    }

    #[test]
    fn report_with_one_skipped_is_succeeded_with_skipped() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Skipped { reason: "dep-not-ready".into() });
        assert_eq!(r.overall_status(), ApplyStatus::SucceededWithSkipped);
    }

    #[test]
    fn report_with_only_skipped_treated_as_empty() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Skipped { reason: "all-deps-not-ready".into() });
        r.push(ApplyOutcome::Skipped { reason: "still-not-ready".into() });
        assert_eq!(
            r.overall_status(),
            ApplyStatus::Empty,
            "only skips means nothing was attempted — equivalent to Empty"
        );
    }

    #[test]
    fn report_with_failed_is_failed_status() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Failed {
            reason: "ApplyFailed".into(),
            error: "boom".into(),
        });
        assert_eq!(r.overall_status(), ApplyStatus::Failed);
        assert!(r.overall_status().is_error());
    }

    #[test]
    fn report_conflict_takes_precedence_over_failed() {
        // Conflict is the worst outcome because it requires operator
        // intervention (takeover, scope narrowing) — never a simple
        // retry. Even with mixed Failed + Conflict, Conflict wins.
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Failed {
            reason: "x".into(),
            error: "y".into(),
        });
        r.push(ApplyOutcome::Conflict {
            conflict_with: "other".into(),
            fields: vec!["spec.replicas".into()],
        });
        assert_eq!(r.overall_status(), ApplyStatus::Conflict);
        assert!(r.overall_status().is_error());
    }

    #[test]
    fn report_counts_partition_total() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Created { payload: dep_ref("b") });
        r.push(ApplyOutcome::Updated {
            payload: dep_ref("c"),
            diff: ApplyDiff::default(),
        });
        r.push(ApplyOutcome::Unchanged { payload: dep_ref("d") });
        r.push(ApplyOutcome::Deleted { ref_: dep_ref("e") });
        r.push(ApplyOutcome::Skipped { reason: "x".into() });
        r.push(ApplyOutcome::Failed {
            reason: "x".into(),
            error: "y".into(),
        });
        r.push(ApplyOutcome::Conflict {
            conflict_with: "x".into(),
            fields: vec![],
        });

        let c = r.counts();
        assert_eq!(c.created, 2);
        assert_eq!(c.updated, 1);
        assert_eq!(c.unchanged, 1);
        assert_eq!(c.deleted, 1);
        assert_eq!(c.skipped, 1);
        assert_eq!(c.failed, 1);
        assert_eq!(c.conflict, 1);
        assert_eq!(c.total(), 8);
        assert_eq!(c.total(), r.len());
    }

    #[test]
    fn report_iter_in_insert_order() {
        let mut r: ApplyReport = ApplyReport::new();
        let names = ["x", "a", "z", "m"];
        for n in &names {
            r.push(ApplyOutcome::Created { payload: dep_ref(n) });
        }
        let iter_order: Vec<&str> = r
            .iter()
            .filter_map(|o| match o {
                ApplyOutcome::Created { payload } => Some(payload.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(iter_order, names);
    }

    #[test]
    fn report_serde_round_trip() {
        let mut r: ApplyReport = ApplyReport::new();
        r.push(ApplyOutcome::Created { payload: dep_ref("a") });
        r.push(ApplyOutcome::Failed {
            reason: "x".into(),
            error: "y".into(),
        });

        let json = serde_json::to_string(&r).unwrap();
        // transparent serialization — should be a JSON array of outcomes.
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));

        let back: ApplyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── ApplyStatus ────────────────────────────────────────────────

    #[test]
    fn apply_status_name_discriminant() {
        assert_eq!(ApplyStatus::Empty.name(), "empty");
        assert_eq!(ApplyStatus::AllSucceeded.name(), "all-succeeded");
        assert_eq!(
            ApplyStatus::SucceededWithSkipped.name(),
            "succeeded-with-skipped"
        );
        assert_eq!(ApplyStatus::Failed.name(), "failed");
        assert_eq!(ApplyStatus::Conflict.name(), "conflict");
    }

    #[test]
    fn apply_status_is_error() {
        assert!(!ApplyStatus::Empty.is_error());
        assert!(!ApplyStatus::AllSucceeded.is_error());
        assert!(!ApplyStatus::SucceededWithSkipped.is_error());
        assert!(ApplyStatus::Failed.is_error());
        assert!(ApplyStatus::Conflict.is_error());
    }

    #[test]
    fn apply_status_serde_kebab_case() {
        let s = ApplyStatus::SucceededWithSkipped;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"succeeded-with-skipped\"");
        let back: ApplyStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    // ── Composition ────────────────────────────────────────────────

    /// Demonstrates the canonical pipeline: enumerate inventory →
    /// apply each → typed outcomes → typed report → typed status.
    #[test]
    fn composes_with_inventory_apply_pipeline() {
        use crate::Inventory;

        // Operator declared three resources.
        let inventory = Inventory::from_iter([dep_ref("a"), dep_ref("b"), dep_ref("c")]);

        // Reconciler applies each; results vary.
        let mut report: ApplyReport<ResourceRef> = ApplyReport::new();
        for r in inventory.iter() {
            let outcome = match r.name.as_str() {
                "a" => ApplyOutcome::Created { payload: r.clone() },
                "b" => ApplyOutcome::Unchanged { payload: r.clone() },
                "c" => ApplyOutcome::Skipped {
                    reason: "dep-not-ready".into(),
                },
                _ => unreachable!(),
            };
            report.push(outcome);
        }

        // Aggregate status routes phase advance.
        assert_eq!(report.overall_status(), ApplyStatus::SucceededWithSkipped);

        let c = report.counts();
        assert_eq!(c.created, 1);
        assert_eq!(c.unchanged, 1);
        assert_eq!(c.skipped, 1);
        assert_eq!(c.changes(), 1); // only Created counts as a state change
    }

    // Composability with shigoto-types::Sink<ApplyOutcome<T>> is the
    // canonical typed audit shape — demonstrated in downstream
    // consumer crates that depend on both magma-converge AND
    // shigoto-types. Magma-converge stays shigoto-types-free at the
    // crate boundary.
}
