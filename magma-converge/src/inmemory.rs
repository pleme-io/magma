//! `InMemoryKvReconciler` — the simplest possible reconciler.
//! State is a `HashMap<String, Value>`. Config is the desired map.
//! `compute_plan` walks both, emits Create/Update/Delete changes.
//! `apply` mutates the in-memory state.
//!
//! Purpose: the testbed. Every trait-law proptest runs against
//! this impl because it's fully deterministic and fully controllable.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;

use crate::{
    build_outcome, change, AppliedChange, Outcome, Plan, Reconciler, ReconcilerError, Action,
};

/// In-memory KV reconciler. State is a HashMap. Thread-safe via Mutex.
pub struct InMemoryKvReconciler {
    state: Mutex<HashMap<String, Value>>,
}

impl Default for InMemoryKvReconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKvReconciler {
    pub fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }

    /// Seed with an initial state (for tests).
    pub fn with_state(state: HashMap<String, Value>) -> Self {
        Self { state: Mutex::new(state) }
    }

    /// Direct (non-trait) state inspection — useful for test asserts.
    pub fn snapshot(&self) -> HashMap<String, Value> {
        self.state.lock().unwrap().clone()
    }
}

#[async_trait]
impl Reconciler for InMemoryKvReconciler {
    fn kind(&self) -> &'static str {
        "inmemory_kv"
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let m = self.state.lock().unwrap().clone();
        Ok(serde_json::to_value(m).map_err(|e| ReconcilerError::ReadState(e.to_string()))?)
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        let desired: HashMap<String, Value> = serde_json::from_value(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("config not a map: {e}")))?;
        let current: HashMap<String, Value> = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state not a map: {e}")))?;

        let mut changes = vec![];

        // Stable iteration order: sort keys.
        let mut all_keys: Vec<&String> = desired.keys().chain(current.keys()).collect();
        all_keys.sort();
        all_keys.dedup();

        for key in all_keys {
            let want = desired.get(key);
            let have = current.get(key);
            let address = format!("kv.{key}");
            match (have, want) {
                (None, Some(v))      => changes.push(change(address, Action::Create, None, Some(v.clone()))),
                (Some(h), None)      => changes.push(change(address, Action::Delete, Some(h.clone()), None)),
                (Some(h), Some(w)) if h != w => {
                    changes.push(change(address, Action::Update, Some(h.clone()), Some(w.clone())));
                }
                (Some(_), Some(_))   => { /* equal — no-op, omit */ }
                (None, None)         => unreachable!(),
            }
        }

        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let started_at = Utc::now();
        let mut applied = vec![];
        let mut state = self.state.lock().unwrap();

        for c in &plan.changes {
            // Address shape: "kv.<key>". Strip the prefix.
            let key = c.address.strip_prefix("kv.").unwrap_or(&c.address);
            match c.action {
                Action::Create | Action::Update => {
                    if let Some(after) = &c.after {
                        state.insert(key.to_string(), after.clone());
                        applied.push(AppliedChange { address: c.address.clone(), action: c.action });
                    }
                }
                Action::Delete => {
                    state.remove(key);
                    applied.push(AppliedChange { address: c.address.clone(), action: c.action });
                }
                Action::Replace => {
                    if let Some(after) = &c.after {
                        state.insert(key.to_string(), after.clone());
                        applied.push(AppliedChange { address: c.address.clone(), action: c.action });
                    }
                }
                Action::NoOp => {}
            }
        }

        Ok(build_outcome(plan, applied, vec![], started_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn fresh_reconciler_has_empty_state() {
        let r = InMemoryKvReconciler::new();
        let state = r.read_state().await.unwrap();
        assert_eq!(state, json!({}));
    }

    #[tokio::test]
    async fn create_plan_against_empty_state() {
        let r = InMemoryKvReconciler::new();
        let config = json!({ "a": 1, "b": 2 });
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 2);
        for c in &plan.changes {
            assert_eq!(c.action, Action::Create);
        }
    }

    #[tokio::test]
    async fn apply_creates_resources_in_state() {
        let r = InMemoryKvReconciler::new();
        let config = json!({ "a": 1 });
        let state  = r.read_state().await.unwrap();
        let plan   = r.compute_plan(&config, &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(r.snapshot().get("a"), Some(&json!(1)));
    }

    #[tokio::test]
    async fn update_plan_emits_typed_diff() {
        let r = InMemoryKvReconciler::with_state(
            [("k".to_string(), json!(1))].into_iter().collect(),
        );
        let config = json!({ "k": 2 });
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        let c = &plan.changes[0];
        assert_eq!(c.action, Action::Update);
        assert_eq!(c.before, Some(json!(1)));
        assert_eq!(c.after,  Some(json!(2)));
    }

    #[tokio::test]
    async fn delete_plan_for_removed_keys() {
        let r = InMemoryKvReconciler::with_state(
            [("doomed".to_string(), json!("bye"))].into_iter().collect(),
        );
        let config = json!({});  // empty desired = remove everything
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Delete);
    }

    #[tokio::test]
    async fn apply_converges_state_to_config() {
        let r = InMemoryKvReconciler::new();
        let config = json!({ "a": 1, "b": 2 });
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        r.apply(&plan).await.unwrap();
        // Next plan against the same config should be a no-op.
        let new_state = r.read_state().await.unwrap();
        let new_plan = r.compute_plan(&config, &new_state).unwrap();
        assert!(new_plan.is_noop(), "expected noop, got {new_plan:?}");
    }

    #[tokio::test]
    async fn detect_drift_returns_compute_plan_against_current_state() {
        let r = InMemoryKvReconciler::with_state(
            [("known".to_string(), json!("old"))].into_iter().collect(),
        );
        let config = json!({ "known": "new" });
        let drift = r.detect_drift(&config).await.unwrap();
        assert_eq!(drift.change_count(), 1);
        assert_eq!(drift.changes[0].action, Action::Update);
    }
}
