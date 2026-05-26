//! `HelmReleaseReconciler` — declarative Helm releases on the
//! convergence substrate. Demonstrates the "version + values vs
//! deployed" reconcile pattern. State is a map of `release_name →
//! { chart, version, values }`. Updates can be triggered by chart
//! bumps, version bumps, or values changes.
//!
//! Mock client in this module (`MockHelmClient`); production impls
//! plug in helm-sdk or shelled-helm behind the same trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Action, AppliedChange, ChangeSeverity, Outcome, Plan, Reconciler, ReconcilerError,
    build_outcome, change_with_severity,
};

// ── Typed release shape ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSpec {
    /// Chart name (e.g. "ingress-nginx/ingress-nginx").
    pub chart: String,
    /// Chart version (semver string).
    pub version: String,
    /// Target namespace.
    pub namespace: String,
    /// Values JSON — typed-arbitrary; equality is structural.
    #[serde(default)]
    pub values: serde_json::Value,
}

// ── Client abstraction ────────────────────────────────────────────

#[async_trait]
pub trait HelmClient: Send + Sync {
    async fn list_releases(&self) -> Result<HashMap<String, ReleaseSpec>, String>;
    async fn install(&self, name: &str, spec: &ReleaseSpec) -> Result<(), String>;
    async fn upgrade(&self, name: &str, spec: &ReleaseSpec) -> Result<(), String>;
    async fn uninstall(&self, name: &str) -> Result<(), String>;
}

/// In-process mock client; used by tests.
#[derive(Default)]
pub struct MockHelmClient {
    state: Mutex<HashMap<String, ReleaseSpec>>,
}

impl MockHelmClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_releases(releases: HashMap<String, ReleaseSpec>) -> Self {
        Self {
            state: Mutex::new(releases),
        }
    }

    pub fn snapshot(&self) -> HashMap<String, ReleaseSpec> {
        self.state.lock().unwrap().clone()
    }
}

#[async_trait]
impl HelmClient for MockHelmClient {
    async fn list_releases(&self) -> Result<HashMap<String, ReleaseSpec>, String> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn install(&self, name: &str, spec: &ReleaseSpec) -> Result<(), String> {
        self.state.lock().unwrap().insert(name.into(), spec.clone());
        Ok(())
    }
    async fn upgrade(&self, name: &str, spec: &ReleaseSpec) -> Result<(), String> {
        self.state.lock().unwrap().insert(name.into(), spec.clone());
        Ok(())
    }
    async fn uninstall(&self, name: &str) -> Result<(), String> {
        self.state.lock().unwrap().remove(name);
        Ok(())
    }
}

// ── Reconciler ────────────────────────────────────────────────────

pub struct HelmReleaseReconciler<C: HelmClient> {
    client: C,
}

impl<C: HelmClient> HelmReleaseReconciler<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
    pub fn client(&self) -> &C {
        &self.client
    }
}

/// Severity for Helm changes: uninstall + replace are Critical
/// (stops serving); version bumps are Functional (running pods get
/// rolled); values-only diffs are typically Functional but can be
/// Cosmetic for label/annotation-only changes.
fn helm_severity(action: Action) -> ChangeSeverity {
    match action {
        Action::Delete | Action::Replace => ChangeSeverity::Critical,
        Action::Create | Action::Update => ChangeSeverity::Functional,
        Action::NoOp => ChangeSeverity::Cosmetic,
    }
}

#[async_trait]
impl<C: HelmClient> Reconciler for HelmReleaseReconciler<C> {
    fn kind(&self) -> &'static str {
        "helm_release"
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let releases = self
            .client
            .list_releases()
            .await
            .map_err(ReconcilerError::ReadState)?;
        serde_json::to_value(releases).map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        let desired: HashMap<String, ReleaseSpec> = serde_json::from_value(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("config: {e}")))?;
        let current: HashMap<String, ReleaseSpec> = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state: {e}")))?;

        let mut all_names: Vec<&String> = desired.keys().chain(current.keys()).collect();
        all_names.sort();
        all_names.dedup();

        let mut changes = vec![];
        for name in all_names {
            let address = format!("helm_release.{name}");
            match (current.get(name), desired.get(name)) {
                (None, Some(w)) => changes.push(change_with_severity(
                    address,
                    Action::Create,
                    helm_severity(Action::Create),
                    None,
                    Some(serde_json::to_value(w).unwrap()),
                )),
                (Some(h), None) => changes.push(change_with_severity(
                    address,
                    Action::Delete,
                    helm_severity(Action::Delete),
                    Some(serde_json::to_value(h).unwrap()),
                    None,
                )),
                (Some(h), Some(w)) if h != w => {
                    // Chart change is structural — treat as Replace
                    // (uninstall+install) since helm doesn't allow
                    // chart swaps via upgrade.
                    let action = if h.chart != w.chart {
                        Action::Replace
                    } else {
                        Action::Update
                    };
                    changes.push(change_with_severity(
                        address,
                        action,
                        helm_severity(action),
                        Some(serde_json::to_value(h).unwrap()),
                        Some(serde_json::to_value(w).unwrap()),
                    ));
                }
                _ => {}
            }
        }

        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let started_at = Utc::now();
        let mut applied = vec![];
        let mut failed = vec![];

        for c in &plan.changes {
            let name = c
                .address
                .strip_prefix("helm_release.")
                .unwrap_or(&c.address);
            let res = match c.action {
                Action::Create => match &c.after {
                    Some(v) => match serde_json::from_value::<ReleaseSpec>(v.clone()) {
                        Ok(spec) => self.client.install(name, &spec).await,
                        Err(e) => Err(format!("decode after: {e}")),
                    },
                    None => Err("create without `after`".into()),
                },
                Action::Update => match &c.after {
                    Some(v) => match serde_json::from_value::<ReleaseSpec>(v.clone()) {
                        Ok(spec) => self.client.upgrade(name, &spec).await,
                        Err(e) => Err(format!("decode after: {e}")),
                    },
                    None => Err("update without `after`".into()),
                },
                Action::Replace => {
                    // uninstall + install
                    match self.client.uninstall(name).await {
                        Ok(()) => match &c.after {
                            Some(v) => match serde_json::from_value::<ReleaseSpec>(v.clone()) {
                                Ok(spec) => self.client.install(name, &spec).await,
                                Err(e) => Err(format!("decode after: {e}")),
                            },
                            None => Err("replace without `after`".into()),
                        },
                        Err(e) => Err(e),
                    }
                }
                Action::Delete => self.client.uninstall(name).await,
                Action::NoOp => continue,
            };
            match res {
                Ok(()) => applied.push(AppliedChange {
                    address: c.address.clone(),
                    action: c.action,
                }),
                Err(e) => failed.push(crate::FailedChange {
                    address: c.address.clone(),
                    action: c.action,
                    error: e,
                }),
            }
        }

        Ok(build_outcome(plan, applied, failed, started_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rel(chart: &str, version: &str, values: Value) -> ReleaseSpec {
        ReleaseSpec {
            chart: chart.into(),
            version: version.into(),
            namespace: "default".into(),
            values,
        }
    }

    #[tokio::test]
    async fn empty_state_yields_no_releases() {
        let r = HelmReleaseReconciler::new(MockHelmClient::new());
        let state = r.read_state().await.unwrap();
        assert_eq!(state, json!({}));
    }

    #[tokio::test]
    async fn install_new_release() {
        let r = HelmReleaseReconciler::new(MockHelmClient::new());
        let mut desired: HashMap<String, ReleaseSpec> = HashMap::new();
        desired.insert(
            "nginx".to_string(),
            rel("ingress-nginx", "4.7.0", json!({"replicaCount": 2})),
        );
        let config = serde_json::to_value(desired).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Create);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Functional);

        let outcome = r.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        assert!(r.client().snapshot().contains_key("nginx"));
    }

    #[tokio::test]
    async fn version_bump_is_update_not_replace() {
        let mut initial = HashMap::new();
        initial.insert("nginx".into(), rel("ingress-nginx", "4.7.0", json!({})));
        let r = HelmReleaseReconciler::new(MockHelmClient::with_releases(initial));
        let mut desired: HashMap<String, ReleaseSpec> = HashMap::new();
        desired.insert("nginx".into(), rel("ingress-nginx", "4.8.0", json!({})));
        let plan = r
            .compute_plan(
                &serde_json::to_value(desired).unwrap(),
                &r.read_state().await.unwrap(),
            )
            .unwrap();
        assert_eq!(plan.changes[0].action, Action::Update);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Functional);
    }

    #[tokio::test]
    async fn chart_swap_is_replace_critical_severity() {
        let mut initial = HashMap::new();
        initial.insert("traffic".into(), rel("ingress-nginx", "4.7.0", json!({})));
        let r = HelmReleaseReconciler::new(MockHelmClient::with_releases(initial));
        let mut desired: HashMap<String, ReleaseSpec> = HashMap::new();
        desired.insert("traffic".into(), rel("envoy-gateway", "1.0.0", json!({})));
        let plan = r
            .compute_plan(
                &serde_json::to_value(desired).unwrap(),
                &r.read_state().await.unwrap(),
            )
            .unwrap();
        assert_eq!(plan.changes[0].action, Action::Replace);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Critical);
    }

    #[tokio::test]
    async fn values_diff_is_update() {
        let mut initial = HashMap::new();
        initial.insert(
            "nginx".into(),
            rel("ingress-nginx", "4.7.0", json!({"replicaCount": 2})),
        );
        let r = HelmReleaseReconciler::new(MockHelmClient::with_releases(initial));
        let mut desired: HashMap<String, ReleaseSpec> = HashMap::new();
        desired.insert(
            "nginx".into(),
            rel("ingress-nginx", "4.7.0", json!({"replicaCount": 5})),
        );
        let plan = r
            .compute_plan(
                &serde_json::to_value(desired).unwrap(),
                &r.read_state().await.unwrap(),
            )
            .unwrap();
        assert_eq!(plan.changes[0].action, Action::Update);
    }

    #[tokio::test]
    async fn uninstall_is_critical_delete() {
        let mut initial = HashMap::new();
        initial.insert("old".into(), rel("legacy", "1.0", json!({})));
        let r = HelmReleaseReconciler::new(MockHelmClient::with_releases(initial));
        let desired: HashMap<String, ReleaseSpec> = HashMap::new();
        let plan = r
            .compute_plan(
                &serde_json::to_value(desired).unwrap(),
                &r.read_state().await.unwrap(),
            )
            .unwrap();
        assert_eq!(plan.changes[0].action, Action::Delete);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Critical);
    }

    #[tokio::test]
    async fn apply_converges() {
        let r = HelmReleaseReconciler::new(MockHelmClient::new());
        let mut desired: HashMap<String, ReleaseSpec> = HashMap::new();
        desired.insert(
            "nginx".to_string(),
            rel("ingress-nginx", "4.7.0", json!({})),
        );
        let config = serde_json::to_value(desired).unwrap();
        let plan = r
            .compute_plan(&config, &r.read_state().await.unwrap())
            .unwrap();
        r.apply(&plan).await.unwrap();
        // Drift is now empty.
        let drift = r.detect_drift(&config).await.unwrap();
        assert!(drift.is_noop());
    }
}
