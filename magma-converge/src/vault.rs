//! `VaultPolicyReconciler` — Vault-style policy reconciliation.
//! Demonstrates the secrets-management API style: a flat namespace
//! of named policies, each carrying a typed body.
//!
//! Policy reconciliation is high-stakes — every change is at least
//! Functional severity, deletes are Critical. The reconciler emits
//! the right severities so downstream drift policies route critical
//! changes through approval.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    build_outcome, change_with_severity, Action, AppliedChange, ChangeSeverity, Outcome, Plan,
    Reconciler, ReconcilerError,
};

// ── Typed policy shape ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBody {
    /// Policy language version (e.g. "v1", "hcl-v1").
    pub version: String,
    /// Policy document — typed-arbitrary; reconciler does
    /// structural equality.
    pub rules:   serde_json::Value,
}

// ── Client abstraction ────────────────────────────────────────────

#[async_trait]
pub trait VaultClient: Send + Sync {
    async fn list_policies(&self) -> Result<HashMap<String, PolicyBody>, String>;
    async fn put_policy(&self, name: &str, body: &PolicyBody) -> Result<(), String>;
    async fn delete_policy(&self, name: &str) -> Result<(), String>;
}

#[derive(Default)]
pub struct MockVaultClient {
    state: Mutex<HashMap<String, PolicyBody>>,
}

impl MockVaultClient {
    pub fn new() -> Self { Self::default() }

    pub fn with_policies(policies: HashMap<String, PolicyBody>) -> Self {
        Self { state: Mutex::new(policies) }
    }

    pub fn snapshot(&self) -> HashMap<String, PolicyBody> {
        self.state.lock().unwrap().clone()
    }
}

#[async_trait]
impl VaultClient for MockVaultClient {
    async fn list_policies(&self) -> Result<HashMap<String, PolicyBody>, String> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn put_policy(&self, name: &str, body: &PolicyBody) -> Result<(), String> {
        self.state.lock().unwrap().insert(name.into(), body.clone());
        Ok(())
    }
    async fn delete_policy(&self, name: &str) -> Result<(), String> {
        self.state.lock().unwrap().remove(name);
        Ok(())
    }
}

// ── Reconciler ────────────────────────────────────────────────────

pub struct VaultPolicyReconciler<C: VaultClient> {
    client: C,
}

impl<C: VaultClient> VaultPolicyReconciler<C> {
    pub fn new(client: C) -> Self { Self { client } }
    pub fn client(&self) -> &C { &self.client }
}

/// Severity rules for policy reconciliation. Every change is at
/// least Functional; deletes are Critical (removing a policy is
/// auth surface area).
fn vault_severity(action: Action) -> ChangeSeverity {
    match action {
        Action::Delete | Action::Replace => ChangeSeverity::Critical,
        Action::Create | Action::Update  => ChangeSeverity::Functional,
        Action::NoOp                     => ChangeSeverity::Cosmetic,
    }
}

#[async_trait]
impl<C: VaultClient> Reconciler for VaultPolicyReconciler<C> {
    fn kind(&self) -> &'static str { "vault_policy" }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let policies = self
            .client
            .list_policies()
            .await
            .map_err(ReconcilerError::ReadState)?;
        serde_json::to_value(policies).map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        let desired: HashMap<String, PolicyBody> = serde_json::from_value(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("config: {e}")))?;
        let current: HashMap<String, PolicyBody> = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state: {e}")))?;

        let mut all_names: Vec<&String> = desired.keys().chain(current.keys()).collect();
        all_names.sort();
        all_names.dedup();

        let mut changes = vec![];
        for name in all_names {
            let address = format!("vault_policy.{name}");
            match (current.get(name), desired.get(name)) {
                (None, Some(w)) => changes.push(change_with_severity(
                    address, Action::Create, vault_severity(Action::Create),
                    None, Some(serde_json::to_value(w).unwrap()),
                )),
                (Some(h), None) => changes.push(change_with_severity(
                    address, Action::Delete, vault_severity(Action::Delete),
                    Some(serde_json::to_value(h).unwrap()), None,
                )),
                (Some(h), Some(w)) if h != w => changes.push(change_with_severity(
                    address, Action::Update, vault_severity(Action::Update),
                    Some(serde_json::to_value(h).unwrap()),
                    Some(serde_json::to_value(w).unwrap()),
                )),
                _ => {}
            }
        }
        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let started_at = Utc::now();
        let mut applied = vec![];
        let mut failed  = vec![];
        for c in &plan.changes {
            let name = c.address.strip_prefix("vault_policy.").unwrap_or(&c.address);
            let res = match c.action {
                Action::Create | Action::Update | Action::Replace => match &c.after {
                    Some(v) => match serde_json::from_value::<PolicyBody>(v.clone()) {
                        Ok(body) => self.client.put_policy(name, &body).await,
                        Err(e) => Err(format!("decode after: {e}")),
                    },
                    None => Err("create/update without `after`".into()),
                },
                Action::Delete => self.client.delete_policy(name).await,
                Action::NoOp   => continue,
            };
            match res {
                Ok(()) => applied.push(AppliedChange { address: c.address.clone(), action: c.action }),
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

    fn policy(version: &str, rules: Value) -> PolicyBody {
        PolicyBody { version: version.into(), rules }
    }

    #[tokio::test]
    async fn empty_state() {
        let r = VaultPolicyReconciler::new(MockVaultClient::new());
        let state = r.read_state().await.unwrap();
        assert_eq!(state, json!({}));
    }

    #[tokio::test]
    async fn create_plan_for_new_policy() {
        let r = VaultPolicyReconciler::new(MockVaultClient::new());
        let mut desired: HashMap<String, PolicyBody> = HashMap::new();
        desired.insert("admin".into(), policy("v1", json!({
            "path": {"secret/*": {"capabilities": ["read","list"]}},
        })));
        let config = serde_json::to_value(desired).unwrap();
        let plan = r.compute_plan(&config, &r.read_state().await.unwrap()).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Create);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Functional);
    }

    #[tokio::test]
    async fn delete_is_critical_severity() {
        let mut initial = HashMap::new();
        initial.insert("old".into(), policy("v1", json!({})));
        let r = VaultPolicyReconciler::new(MockVaultClient::with_policies(initial));
        let desired: HashMap<String, PolicyBody> = HashMap::new();
        let plan = r.compute_plan(
            &serde_json::to_value(desired).unwrap(),
            &r.read_state().await.unwrap(),
        ).unwrap();
        assert_eq!(plan.changes[0].action, Action::Delete);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Critical);
    }

    #[tokio::test]
    async fn update_plan_when_rules_differ() {
        let mut initial: HashMap<String, PolicyBody> = HashMap::new();
        initial.insert("ro".into(), policy("v1", json!({"a": 1})));
        let r = VaultPolicyReconciler::new(MockVaultClient::with_policies(initial));
        let mut desired: HashMap<String, PolicyBody> = HashMap::new();
        desired.insert("ro".into(), policy("v1", json!({"a": 2})));
        let plan = r.compute_plan(
            &serde_json::to_value(desired).unwrap(),
            &r.read_state().await.unwrap(),
        ).unwrap();
        assert_eq!(plan.changes[0].action, Action::Update);
    }

    #[tokio::test]
    async fn apply_converges() {
        let r = VaultPolicyReconciler::new(MockVaultClient::new());
        let mut desired: HashMap<String, PolicyBody> = HashMap::new();
        desired.insert("p".into(), policy("v1", json!({})));
        let config = serde_json::to_value(desired).unwrap();
        let plan = r.compute_plan(&config, &r.read_state().await.unwrap()).unwrap();
        r.apply(&plan).await.unwrap();
        let drift = r.detect_drift(&config).await.unwrap();
        assert!(drift.is_noop());
    }
}
