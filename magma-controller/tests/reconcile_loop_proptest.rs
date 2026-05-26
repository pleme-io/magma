//! Property-based proofs for the universal reconcile loop.
//!
//! `ReconcileController.reconcile(config)` composes Reconciler +
//! Budget + Drift + FSM + Stream + Bundle + Metrics into the
//! universal operator surface. Compliance teams rely on it to
//! deliver:
//!
//! * A typed `ControllerOutcome` carrying a verified Bundle.
//! * A lifecycle that always lands in a terminal phase (Stable /
//!   Refused / Approving / Failed).
//! * A bundle whose plan_id matches the result's plan_id (no
//!   identity drift between subsystems).
//! * `fully_succeeded()` only true when the whole loop succeeded
//!   end-to-end (Stable + applied + no failures).
//!
//! These proptests turn each of those into a proven theorem over
//! random KV configs.

use std::collections::HashMap;
use std::sync::Arc;

use magma_budget::{BudgetedReconciler, ConcurrencyLimit, RetryPolicy};
use magma_controller::ReconcileController;
use magma_converge::inmemory::InMemoryKvReconciler;
use magma_drift::{DriftPolicy, ReconcileResult};
use magma_fsm::Phase;
use magma_metrics::Metrics;
use magma_stream::PlanStream;
use prometheus::Registry;
use proptest::prelude::*;
use serde_json::{Value, json};

// ── Random config generator ────────────────────────────────────────

fn arb_kv_config() -> impl Strategy<Value = Value> {
    proptest::collection::hash_map(
        "[a-z][a-z0-9]{0,5}",
        prop_oneof![
            (0i64..1000).prop_map(|n| json!(n)),
            "[a-z]{1,8}".prop_map(Value::String),
            Just(json!(true)),
            Just(json!(null)),
        ],
        0..=6,
    )
    .prop_map(|m| {
        let obj: serde_json::Map<String, Value> = m.into_iter().collect();
        Value::Object(obj)
    })
}

// Fresh controller per test (each proptest case wants its own
// metrics registry to avoid name collisions on retest).
fn fresh_controller(
    seeded_state: Option<HashMap<String, Value>>,
    policy: DriftPolicy,
) -> ReconcileController<InMemoryKvReconciler> {
    let inner = match seeded_state {
        Some(s) => InMemoryKvReconciler::with_state(s),
        None => InMemoryKvReconciler::new(),
    };
    let budgeted = BudgetedReconciler::new(inner, ConcurrencyLimit::new(4), RetryPolicy::none());
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::register(&registry).unwrap());
    let stream = Arc::new(PlanStream::new());
    ReconcileController::new(budgeted, policy, stream, metrics, "ws-test")
}

// ── Property 1: bundle plan_id matches result plan_id ──────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn bundle_plan_id_matches_result(cfg in arb_kv_config()) {
        let outcome = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            c.reconcile(&cfg).await
        }).unwrap();
        prop_assert_eq!(outcome.bundle.plan_id(), outcome.result.plan_id());
    }
}

// ── Property 2: bundle verifies ────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn bundle_verifies(cfg in arb_kv_config()) {
        let outcome = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            c.reconcile(&cfg).await
        }).unwrap();
        outcome.bundle.verify().unwrap_or_else(|e| panic!("bundle.verify(): {e:?}"));
    }
}

// ── Property 3: lifecycle ends in a terminal-or-approving phase ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn lifecycle_lands_in_decision_phase(cfg in arb_kv_config()) {
        let outcome = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            c.reconcile(&cfg).await
        }).unwrap();
        let phase = outcome.lifecycle.current;
        prop_assert!(
            matches!(phase, Phase::Stable | Phase::Refused | Phase::Approving | Phase::Failed),
            "lifecycle landed in non-decision phase: {phase:?}",
        );
    }
}

// ── Property 4: fully_succeeded contract — Stable + (NoChange|Applied)

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn fully_succeeded_iff_stable_and_no_change_or_applied(cfg in arb_kv_config()) {
        let outcome = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            c.reconcile(&cfg).await
        }).unwrap();

        let lifecycle_stable = outcome.lifecycle.current == Phase::Stable;
        let kind_ok = matches!(
            &outcome.result,
            ReconcileResult::NoChange { .. } | ReconcileResult::Applied { .. },
        );
        prop_assert_eq!(outcome.fully_succeeded(), lifecycle_stable && kind_ok);
        // Cross-check: lifecycle Stable iff result is NoChange/Applied
        // under conservative policy + clean InMemoryKv (no failures).
        prop_assert_eq!(lifecycle_stable, kind_ok);
    }
}

// ── Property 5: reconcile is deterministic over repeated calls ─────
//
// Calling reconcile twice in sequence on the same controller should
// produce the same plan_id the second time (state converged in the
// first call; the second sees empty diff).

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn second_reconcile_converges_to_no_change(cfg in arb_kv_config()) {
        let (first, second) = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            let first  = c.reconcile(&cfg).await.unwrap();
            let second = c.reconcile(&cfg).await.unwrap();
            (first, second)
        });
        // First call may have applied changes. Second must converge.
        match &second.result {
            ReconcileResult::NoChange { .. } => {} // expected
            ReconcileResult::HeldForApproval { .. } => {
                // Acceptable: if first hit approval, state didn't
                // progress, so second hits the same plan again.
                let was_held = matches!(first.result, ReconcileResult::HeldForApproval { .. });
                prop_assert!(was_held, "second held but first wasn't: {:?}", first.result);
            }
            ReconcileResult::Refused { .. } => {
                let was_refused = matches!(first.result, ReconcileResult::Refused { .. });
                prop_assert!(was_refused, "second refused but first wasn't: {:?}", first.result);
            }
            other => panic!("second reconcile not converged: {other:?}"),
        }
    }
}

// ── Property 6: lifecycle history is non-empty ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn lifecycle_has_at_least_one_transition(cfg in arb_kv_config()) {
        let outcome = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let c = fresh_controller(None, DriftPolicy::conservative_default());
            c.reconcile(&cfg).await
        }).unwrap();
        prop_assert!(
            !outcome.lifecycle.history.is_empty(),
            "controller produced an empty lifecycle history",
        );
        // First transition is always Idle → Planning.
        let first = outcome.lifecycle.history.first().unwrap();
        prop_assert_eq!(first.from, Phase::Idle);
        prop_assert_eq!(first.to,   Phase::Planning);
    }
}
