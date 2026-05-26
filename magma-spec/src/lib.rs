//! magma-spec — speculative execution + plan comparison.
//!
//! Magma's `compute_plan` is a pure function — given a config and
//! a state, it produces a deterministic Plan. That property lets
//! us answer "what would change?" questions without touching live
//! state:
//!
//! * `plan_against_synthetic(reconciler, config, fake_state)` —
//!   plan as if state were this hypothetical.
//! * `compare_plans(a, b)` — typed diff between two plans
//!   (e.g. dev vs prod environmental comparison).
//! * `what_if(reconciler, config, current, mutation)` — apply a
//!   hypothetical mutation to the current state, then plan.
//!
//! All pure functions; zero API calls. Powers IDE-level UX:
//! "preview this PR's plan", "compare against last week", "what
//! happens if we accept this drift".

#![deny(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use magma_converge::{Change, Plan, Reconciler, ReconcilerError};

// ── Synthetic state planning ──────────────────────────────────────

/// Plan against a fake state, without reading the real backend.
/// Useful for IDE "what if everything was empty?" / "what if we had
/// these resources?" workflows.
pub fn plan_against_synthetic<R: Reconciler>(
    reconciler: &R,
    config: &Value,
    fake_state: &Value,
) -> Result<Plan, ReconcilerError> {
    reconciler.compute_plan(config, fake_state)
}

// ── Plan comparison ───────────────────────────────────────────────

/// A typed diff between two Plans. Used for "what changed between
/// last reconcile and this one" or "dev plan vs prod plan".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanComparison {
    /// Plan A's id (the "before" baseline).
    pub before: magma_converge::PlanId,
    /// Plan B's id (the "after").
    pub after: magma_converge::PlanId,
    /// Changes only in A (i.e. would have happened but didn't).
    pub only_in_before: Vec<Change>,
    /// Changes only in B (newly introduced).
    pub only_in_after: Vec<Change>,
    /// Changes present in both with the same shape (consistent).
    pub in_both: Vec<Change>,
    /// Changes whose action or before/after differs between A and B.
    pub diverged: Vec<PlanDivergence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDivergence {
    pub address: String,
    pub before: Change,
    pub after: Change,
}

impl PlanComparison {
    /// True iff the two plans are identical in shape (same changes).
    pub fn is_identical(&self) -> bool {
        self.only_in_before.is_empty() && self.only_in_after.is_empty() && self.diverged.is_empty()
    }

    /// Counts (only_in_before, only_in_after, diverged, in_both).
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.only_in_before.len(),
            self.only_in_after.len(),
            self.diverged.len(),
            self.in_both.len(),
        )
    }
}

/// Typed diff between two plans, indexed by Change.address.
pub fn compare_plans(a: &Plan, b: &Plan) -> PlanComparison {
    let a_by: HashMap<&str, &Change> = a.changes.iter().map(|c| (c.address.as_str(), c)).collect();
    let b_by: HashMap<&str, &Change> = b.changes.iter().map(|c| (c.address.as_str(), c)).collect();

    let mut only_in_before = vec![];
    let mut only_in_after = vec![];
    let mut in_both = vec![];
    let mut diverged = vec![];

    let mut all_keys: Vec<&str> = a_by.keys().chain(b_by.keys()).copied().collect();
    all_keys.sort();
    all_keys.dedup();

    for key in all_keys {
        match (a_by.get(key), b_by.get(key)) {
            (Some(ca), None) => only_in_before.push((*ca).clone()),
            (None, Some(cb)) => only_in_after.push((*cb).clone()),
            (Some(ca), Some(cb)) => {
                if changes_equal(ca, cb) {
                    in_both.push((*ca).clone());
                } else {
                    diverged.push(PlanDivergence {
                        address: key.to_string(),
                        before: (*ca).clone(),
                        after: (*cb).clone(),
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }

    PlanComparison {
        before: a.id.clone(),
        after: b.id.clone(),
        only_in_before,
        only_in_after,
        in_both,
        diverged,
    }
}

fn changes_equal(a: &Change, b: &Change) -> bool {
    a.action == b.action && a.severity == b.severity && a.before == b.before && a.after == b.after
}

// ── What-if mutation ──────────────────────────────────────────────

/// A mutation applied to a hypothetical state before planning.
#[derive(Debug, Clone)]
pub enum StateMutation {
    /// Insert/replace one key in the state JSON (top-level object).
    SetKey(String, Value),
    /// Remove a key from the state.
    RemoveKey(String),
    /// Replace the entire state with a new value.
    Replace(Value),
}

impl StateMutation {
    pub fn apply(&self, state: &Value) -> Value {
        match self {
            Self::Replace(v) => v.clone(),
            Self::SetKey(k, v) => {
                let mut obj = state.as_object().cloned().unwrap_or_default();
                obj.insert(k.clone(), v.clone());
                Value::Object(obj)
            }
            Self::RemoveKey(k) => {
                let mut obj = state.as_object().cloned().unwrap_or_default();
                obj.remove(k);
                Value::Object(obj)
            }
        }
    }
}

/// Plan as if `mutation` had been applied to `current_state` first.
pub fn what_if<R: Reconciler>(
    reconciler: &R,
    config: &Value,
    current_state: &Value,
    mutation: &StateMutation,
) -> Result<Plan, ReconcilerError> {
    let hypothetical = mutation.apply(current_state);
    reconciler.compute_plan(config, &hypothetical)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::inmemory::InMemoryKvReconciler;
    use magma_converge::{Action, Reconciler};
    use serde_json::json;

    #[tokio::test]
    async fn plan_against_synthetic_does_not_touch_real_state() {
        let r = InMemoryKvReconciler::new(); // real state is empty
        let fake = json!({ "preloaded": "yes" });
        let plan = plan_against_synthetic(&r, &json!({ "preloaded": "yes" }), &fake).unwrap();
        // Same in fake → plan is empty.
        assert!(plan.is_noop());
        // Real state remains untouched.
        assert!(r.snapshot().is_empty());
    }

    #[tokio::test]
    async fn compare_plans_identical() {
        let r = InMemoryKvReconciler::new();
        let cfg = json!({ "a": 1 });
        let state = r.read_state().await.unwrap();
        let p1 = r.compute_plan(&cfg, &state).unwrap();
        let p2 = r.compute_plan(&cfg, &state).unwrap();
        let cmp = compare_plans(&p1, &p2);
        assert!(cmp.is_identical());
        assert_eq!(cmp.counts(), (0, 0, 0, p1.changes.len()));
    }

    #[tokio::test]
    async fn compare_plans_detects_divergence() {
        let r = InMemoryKvReconciler::new();
        // Plan A: would create a=1
        let p_a = r.compute_plan(&json!({"a": 1}), &json!({})).unwrap();
        // Plan B: would create a=2 (same key, different after-value)
        let p_b = r.compute_plan(&json!({"a": 2}), &json!({})).unwrap();
        let cmp = compare_plans(&p_a, &p_b);
        assert!(!cmp.is_identical());
        assert_eq!(cmp.diverged.len(), 1);
        assert_eq!(cmp.diverged[0].address, "kv.a");
    }

    #[tokio::test]
    async fn compare_plans_only_in_before_or_after() {
        let r = InMemoryKvReconciler::new();
        // Plan A: creates a + b
        let p_a = r
            .compute_plan(&json!({"a": 1, "b": 2}), &json!({}))
            .unwrap();
        // Plan B: creates a + c (b dropped, c added)
        let p_b = r
            .compute_plan(&json!({"a": 1, "c": 3}), &json!({}))
            .unwrap();
        let cmp = compare_plans(&p_a, &p_b);
        // a in both; b only in A; c only in B
        assert_eq!(cmp.in_both.len(), 1);
        assert_eq!(
            cmp.only_in_before
                .iter()
                .filter(|c| c.address == "kv.b")
                .count(),
            1
        );
        assert_eq!(
            cmp.only_in_after
                .iter()
                .filter(|c| c.address == "kv.c")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn what_if_with_set_key() {
        let r = InMemoryKvReconciler::new();
        let cfg = json!({ "a": 1, "b": 2 });
        let current = r.read_state().await.unwrap();
        let mutation = StateMutation::SetKey("a".into(), json!(1));
        let plan = what_if(&r, &cfg, &current, &mutation).unwrap();
        // a is now satisfied → only b is a create.
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].address, "kv.b");
    }

    #[tokio::test]
    async fn what_if_with_remove_key() {
        let r = InMemoryKvReconciler::with_state(
            [("doomed".to_string(), json!(1))].into_iter().collect(),
        );
        let current = r.read_state().await.unwrap();
        let cfg = json!({ "doomed": 1 });
        let mutation = StateMutation::RemoveKey("doomed".into());
        let plan = what_if(&r, &cfg, &current, &mutation).unwrap();
        // After removing 'doomed' from hypothetical state, plan
        // sees a missing key and emits Create.
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Create);
    }

    #[tokio::test]
    async fn what_if_with_replace_full_state() {
        let r = InMemoryKvReconciler::new();
        let cfg = json!({ "a": 1 });
        let plan = what_if(
            &r,
            &cfg,
            &json!({}),
            &StateMutation::Replace(json!({ "a": 1 })),
        )
        .unwrap();
        // Hypothetical state already has a=1 → noop.
        assert!(plan.is_noop());
    }
}
