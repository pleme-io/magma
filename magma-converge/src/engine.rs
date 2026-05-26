//! `ConvergeEngine` — the universal convergence engine that the
//! operator (or any consumer) instantiates. Holds a registry of
//! reconcilers indexed by `kind`, routes typed `(kind, config)`
//! pairs to the right impl, and provides cross-reconciler
//! operations (drift sweep, multi-kind reconcile).

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::{Outcome, Plan, Reconciler, ReconcilerError, SharedReconciler};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("unknown reconciler kind: {0}")]
    UnknownKind(String),
    #[error("reconciler error: {0}")]
    Reconciler(#[from] ReconcilerError),
}

/// Holds the registry of typed reconcilers + dispatches to the
/// right kind.
#[derive(Default)]
pub struct ConvergeEngine {
    reconcilers: HashMap<String, SharedReconciler>,
}

impl ConvergeEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a reconciler. The kind string comes from the
    /// reconciler itself (`Reconciler::kind()`).
    pub fn register<R: Reconciler + 'static>(&mut self, reconciler: R) -> &mut Self {
        let kind = reconciler.kind().to_string();
        self.reconcilers.insert(kind, Arc::new(reconciler));
        self
    }

    /// Register an already-Arc'd reconciler (e.g. for sharing one
    /// instance across engines).
    pub fn register_shared(&mut self, kind: &str, reconciler: SharedReconciler) -> &mut Self {
        self.reconcilers.insert(kind.to_string(), reconciler);
        self
    }

    /// Number of registered reconciler kinds.
    pub fn len(&self) -> usize {
        self.reconcilers.len()
    }

    /// True iff no reconcilers are registered.
    pub fn is_empty(&self) -> bool {
        self.reconcilers.is_empty()
    }

    /// Look up a reconciler by kind.
    pub fn get(&self, kind: &str) -> Option<&SharedReconciler> {
        self.reconcilers.get(kind)
    }

    /// Every registered kind label.
    pub fn kinds(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.reconcilers.keys().map(String::as_str).collect();
        v.sort();
        v
    }

    /// Read state for one kind.
    pub async fn read_state(&self, kind: &str) -> Result<Value, EngineError> {
        let r = self
            .get(kind)
            .ok_or_else(|| EngineError::UnknownKind(kind.into()))?;
        r.read_state().await.map_err(Into::into)
    }

    /// Compute a plan for one kind.
    pub fn compute_plan(
        &self,
        kind: &str,
        config: &Value,
        state: &Value,
    ) -> Result<Plan, EngineError> {
        let r = self
            .get(kind)
            .ok_or_else(|| EngineError::UnknownKind(kind.into()))?;
        r.compute_plan(config, state).map_err(Into::into)
    }

    /// Detect drift for one kind.
    pub async fn detect_drift(&self, kind: &str, config: &Value) -> Result<Plan, EngineError> {
        let r = self
            .get(kind)
            .ok_or_else(|| EngineError::UnknownKind(kind.into()))?;
        r.detect_drift(config).await.map_err(Into::into)
    }

    /// Apply a plan for one kind.
    pub async fn apply(&self, kind: &str, plan: &Plan) -> Result<Outcome, EngineError> {
        let r = self
            .get(kind)
            .ok_or_else(|| EngineError::UnknownKind(kind.into()))?;
        r.apply(plan).await.map_err(Into::into)
    }

    /// Drift-sweep across every registered reconciler, given a
    /// per-kind config. Skips kinds with no config supplied. Each
    /// kind's drift plan is collected; failures are surfaced via
    /// the returned `Vec<(kind, Result<Plan, EngineError>)>`.
    pub async fn drift_sweep(
        &self,
        configs: &HashMap<String, Value>,
    ) -> Vec<(String, Result<Plan, EngineError>)> {
        let mut out = vec![];
        for (kind, cfg) in configs {
            let res = self.detect_drift(kind, cfg).await;
            out.push((kind.clone(), res));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmemory::InMemoryKvReconciler;
    use serde_json::json;

    #[tokio::test]
    async fn engine_routes_to_registered_kind() {
        let mut engine = ConvergeEngine::new();
        engine.register(InMemoryKvReconciler::new());
        assert_eq!(engine.len(), 1);

        let config = json!({ "a": 1 });
        let state = engine.read_state("inmemory_kv").await.unwrap();
        let plan = engine.compute_plan("inmemory_kv", &config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        let outcome = engine.apply("inmemory_kv", &plan).await.unwrap();
        assert!(outcome.fully_succeeded());
    }

    #[tokio::test]
    async fn unknown_kind_errors_loudly() {
        let engine = ConvergeEngine::new();
        let result = engine.read_state("nonexistent").await;
        match result {
            Err(EngineError::UnknownKind(k)) => assert_eq!(k, "nonexistent"),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn drift_sweep_runs_each_kind_in_isolation() {
        let mut engine = ConvergeEngine::new();
        engine.register(InMemoryKvReconciler::new());

        let mut configs = HashMap::new();
        configs.insert("inmemory_kv".to_string(), json!({ "a": 1 }));
        configs.insert("ghost_kind".to_string(), json!({}));

        let results = engine.drift_sweep(&configs).await;
        assert_eq!(results.len(), 2);
        // inmemory_kv should yield a 1-change plan; ghost_kind unknown.
        let by_kind: HashMap<&str, &Result<Plan, EngineError>> =
            results.iter().map(|(k, r)| (k.as_str(), r)).collect();
        assert!(by_kind["inmemory_kv"].is_ok());
        assert!(by_kind["ghost_kind"].is_err());
    }

    #[tokio::test]
    async fn engine_kinds_returns_sorted_labels() {
        let mut engine = ConvergeEngine::new();
        engine.register(InMemoryKvReconciler::new());
        // For now we only have inmemory_kv registered; verify sort.
        assert_eq!(engine.kinds(), vec!["inmemory_kv"]);
    }
}
