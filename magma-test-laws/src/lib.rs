//! magma-test-laws — reusable `Reconciler` law test helpers.
//!
//! Every `Reconciler` impl in the convergence ecosystem must obey
//! the five universal laws (see `magma_converge::Reconciler` docs).
//! This crate packages each law as a typed test helper that any
//! impl can call:
//!
//! ```no_run
//! # use magma_test_laws::*;
//! # use magma_converge::inmemory::InMemoryKvReconciler;
//! # use serde_json::json;
//! #[tokio::test]
//! async fn obeys_all_laws() {
//!     let r = InMemoryKvReconciler::new();
//!     assert_read_state_idempotent(&r).await;
//!     assert_empty_plan_noop(&r, &json!({})).await;
//!     assert_apply_converges(&r, &json!({"a": 1})).await;
//!     assert_plan_id_deterministic(&r, &json!({"a": 1}), &json!({})).await;
//!     assert_plan_id_differs_with_changed_config(
//!         &r, &json!({"a": 1}), &json!({"a": 2}), &json!({}),
//!     ).await;
//! }
//! ```
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §VII. The helpers panic
//! with a clear message on law violation — they're meant to be
//! used INSIDE `#[tokio::test]` functions, not standalone.

#![deny(unsafe_code)]

use magma_converge::Reconciler;
use serde_json::Value;

/// Law 1: `read_state` is referentially transparent. Two reads of
/// an unmodified system return equal JSON.
pub async fn assert_read_state_idempotent<R: Reconciler>(r: &R) {
    let s1 = r.read_state().await.expect("read_state #1 failed");
    let s2 = r.read_state().await.expect("read_state #2 failed");
    assert_eq!(
        s1, s2,
        "law violated: read_state is not referentially transparent for kind={}",
        r.kind(),
    );
}

/// Law 2: empty config (or no-change config) yields a no-op plan
/// that doesn't mutate state when applied.
pub async fn assert_empty_plan_noop<R: Reconciler>(r: &R, empty_config: &Value) {
    let state_before = r
        .read_state()
        .await
        .expect("read_state for empty-plan check failed");
    let plan = r
        .compute_plan(empty_config, &state_before)
        .expect("compute_plan for empty config failed");
    assert!(
        plan.is_noop(),
        "law violated: empty config produced non-empty plan for kind={}: {:?}",
        r.kind(),
        plan.changes,
    );
    r.apply(&plan).await.expect("apply noop plan failed");
    let state_after = r
        .read_state()
        .await
        .expect("read_state after noop apply failed");
    assert_eq!(
        state_before, state_after,
        "law violated: noop apply mutated state for kind={}",
        r.kind(),
    );
}

/// Law 3: apply converges. After applying the plan computed from
/// `(config, current_state)`, the next `detect_drift(config)`
/// produces an empty plan.
pub async fn assert_apply_converges<R: Reconciler>(r: &R, config: &Value) {
    let state = r.read_state().await.expect("read_state for converge failed");
    let plan = r
        .compute_plan(config, &state)
        .expect("compute_plan for converge failed");
    r.apply(&plan).await.expect("apply for converge failed");
    let drift = r
        .detect_drift(config)
        .await
        .expect("detect_drift after apply failed");
    assert!(
        drift.is_noop(),
        "law violated: post-apply drift is non-empty for kind={}: {:?}",
        r.kind(),
        drift.changes,
    );
}

/// Law 4: `compute_plan(config, state)` is deterministic. Two
/// invocations with identical inputs produce identical `plan_id`s
/// and identical change shapes.
pub async fn assert_plan_id_deterministic<R: Reconciler>(
    r: &R,
    config: &Value,
    state:  &Value,
) {
    let p1 = r
        .compute_plan(config, state)
        .expect("compute_plan #1 failed");
    let p2 = r
        .compute_plan(config, state)
        .expect("compute_plan #2 failed");
    assert_eq!(
        p1.id, p2.id,
        "law violated: compute_plan is non-deterministic for kind={}",
        r.kind(),
    );
    assert_eq!(
        p1.changes, p2.changes,
        "law violated: compute_plan change shape differs across calls for kind={}",
        r.kind(),
    );
}

/// Law 5: changing the config (when the resulting plan changes)
/// produces a different `plan_id`. If two configs yield identical
/// change shapes, plan_ids are equal; if different, plan_ids differ.
pub async fn assert_plan_id_differs_with_changed_config<R: Reconciler>(
    r: &R,
    config_a: &Value,
    config_b: &Value,
    state:    &Value,
) {
    let p_a = r
        .compute_plan(config_a, state)
        .expect("compute_plan A failed");
    let p_b = r
        .compute_plan(config_b, state)
        .expect("compute_plan B failed");
    if p_a.changes == p_b.changes {
        assert_eq!(
            p_a.id, p_b.id,
            "law violated: identical change shape but different plan_id for kind={}",
            r.kind(),
        );
    } else {
        assert_ne!(
            p_a.id, p_b.id,
            "law violated: different change shape but identical plan_id for kind={}",
            r.kind(),
        );
    }
}

/// Run all five laws back-to-back. Convenience for impls that
/// don't need bespoke per-law setup.
///
/// `config_a` and `config_b` should be DIFFERENT configs against the
/// same state (so law 5 has something to compare).
pub async fn assert_all_laws<R: Reconciler>(
    r:        &R,
    config_a: &Value,
    config_b: &Value,
    state:    &Value,
    empty_config: &Value,
) {
    assert_read_state_idempotent(r).await;
    assert_empty_plan_noop(r, empty_config).await;
    assert_apply_converges(r, config_a).await;
    assert_plan_id_deterministic(r, config_a, state).await;
    assert_plan_id_differs_with_changed_config(r, config_a, config_b, state).await;
}

// ── Tests for the helpers themselves ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::inmemory::InMemoryKvReconciler;
    use serde_json::json;

    #[tokio::test]
    async fn helpers_pass_for_inmemory_reconciler() {
        let r = InMemoryKvReconciler::new();
        assert_all_laws(
            &r,
            &json!({"a": 1}),
            &json!({"a": 2}),
            &json!({}),
            &json!({}),
        ).await;
    }

    #[tokio::test]
    async fn law_helpers_can_be_used_independently() {
        let r = InMemoryKvReconciler::new();
        assert_read_state_idempotent(&r).await;
        assert_empty_plan_noop(&r, &json!({})).await;
    }

    #[tokio::test]
    #[should_panic(expected = "law violated")]
    async fn helper_panics_on_violation() {
        // BrokenReconciler emits a non-noop plan even when given
        // the empty config — violating law 2.
        use async_trait::async_trait;
        use magma_converge::{change, Action, Plan, ReconcilerError};

        struct BrokenReconciler;

        #[async_trait]
        impl Reconciler for BrokenReconciler {
            fn kind(&self) -> &'static str { "broken" }
            async fn read_state(&self) -> Result<Value, ReconcilerError> {
                Ok(json!({}))
            }
            fn compute_plan(&self, _config: &Value, _state: &Value) -> Result<Plan, ReconcilerError> {
                Ok(Plan::new("broken", vec![
                    change("x", Action::Create, None, Some(json!(1))),
                ]))
            }
            async fn apply(&self, _plan: &Plan) -> Result<magma_converge::Outcome, ReconcilerError> {
                Ok(magma_converge::Outcome {
                    plan_id:     magma_converge::PlanId("0".into()),
                    kind:        "broken".into(),
                    applied:     vec![],
                    failed:      vec![],
                    started_at:  chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                })
            }
        }

        assert_empty_plan_noop(&BrokenReconciler, &json!({})).await;
    }
}
