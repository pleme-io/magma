//! `GithubRepoReconciler` — reconciles GitHub repository settings
//! (description, visibility, default branch, topics, branch
//! protection). Demonstrates the REST-CRUD style of reconciler.
//!
//! The client is abstracted behind `GithubClient` so tests use
//! `MockGithubClient` without touching real GitHub. Production
//! impl plugs in `octocrab` or `gh` HTTP behind the same trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    build_outcome, change, AppliedChange, Outcome, Plan, Reconciler, ReconcilerError, Action,
};

// ── Typed repo shape ──────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSettings {
    pub description:    Option<String>,
    pub private:        bool,
    pub default_branch: String,
    /// Sorted, deduped.
    pub topics:         Vec<String>,
}

impl RepoSettings {
    fn canonical(mut self) -> Self {
        self.topics.sort();
        self.topics.dedup();
        self
    }
}

// ── Client abstraction ────────────────────────────────────────────

#[async_trait]
pub trait GithubClient: Send + Sync {
    async fn list_repos(&self) -> Result<HashMap<String, RepoSettings>, String>;
    async fn create_repo(&self, name: &str, settings: &RepoSettings) -> Result<(), String>;
    async fn update_repo(&self, name: &str, settings: &RepoSettings) -> Result<(), String>;
    async fn delete_repo(&self, name: &str) -> Result<(), String>;
}

/// In-process mock client. Used by tests + reference impl.
#[derive(Default)]
pub struct MockGithubClient {
    /// Hidden internal "GitHub" state. Mutex for thread-safety.
    state: Mutex<HashMap<String, RepoSettings>>,
    /// Optional injectable failure on the next mutation call.
    next_failure: Mutex<Option<String>>,
}

impl MockGithubClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_repos(repos: HashMap<String, RepoSettings>) -> Self {
        Self {
            state: Mutex::new(repos.into_iter().map(|(k, v)| (k, v.canonical())).collect()),
            next_failure: Mutex::new(None),
        }
    }

    /// Inject a failure on the next mutating call.
    pub fn fail_next(&self, msg: &str) {
        *self.next_failure.lock().unwrap() = Some(msg.to_string());
    }

    fn maybe_fail(&self) -> Result<(), String> {
        if let Some(msg) = self.next_failure.lock().unwrap().take() {
            return Err(msg);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> HashMap<String, RepoSettings> {
        self.state.lock().unwrap().clone()
    }
}

#[async_trait]
impl GithubClient for MockGithubClient {
    async fn list_repos(&self) -> Result<HashMap<String, RepoSettings>, String> {
        Ok(self.state.lock().unwrap().clone())
    }

    async fn create_repo(&self, name: &str, settings: &RepoSettings) -> Result<(), String> {
        self.maybe_fail()?;
        self.state
            .lock()
            .unwrap()
            .insert(name.to_string(), settings.clone().canonical());
        Ok(())
    }

    async fn update_repo(&self, name: &str, settings: &RepoSettings) -> Result<(), String> {
        self.maybe_fail()?;
        self.state
            .lock()
            .unwrap()
            .insert(name.to_string(), settings.clone().canonical());
        Ok(())
    }

    async fn delete_repo(&self, name: &str) -> Result<(), String> {
        self.maybe_fail()?;
        self.state.lock().unwrap().remove(name);
        Ok(())
    }
}

// ── Reconciler ────────────────────────────────────────────────────

pub struct GithubRepoReconciler<C: GithubClient> {
    client: C,
}

impl<C: GithubClient> GithubRepoReconciler<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &C {
        &self.client
    }
}

#[async_trait]
impl<C: GithubClient> Reconciler for GithubRepoReconciler<C> {
    fn kind(&self) -> &'static str {
        "github_repo"
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let repos = self
            .client
            .list_repos()
            .await
            .map_err(ReconcilerError::ReadState)?;
        let canonical: HashMap<String, RepoSettings> = repos
            .into_iter()
            .map(|(k, v)| (k, v.canonical()))
            .collect();
        serde_json::to_value(canonical).map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        let desired: HashMap<String, RepoSettings> = serde_json::from_value(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("config: {e}")))?;
        let current: HashMap<String, RepoSettings> = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state: {e}")))?;

        // Canonicalize both sides so topic order doesn't trigger diffs.
        let desired: HashMap<String, RepoSettings> = desired
            .into_iter()
            .map(|(k, v)| (k, v.canonical()))
            .collect();
        let current: HashMap<String, RepoSettings> = current
            .into_iter()
            .map(|(k, v)| (k, v.canonical()))
            .collect();

        let mut changes = vec![];
        let mut all_names: Vec<&String> =
            desired.keys().chain(current.keys()).collect();
        all_names.sort();
        all_names.dedup();

        for name in all_names {
            let address = format!("github_repo.{name}");
            match (current.get(name), desired.get(name)) {
                (None, Some(want)) => changes.push(change(
                    address, Action::Create, None,
                    Some(serde_json::to_value(want).unwrap()),
                )),
                (Some(have), None) => changes.push(change(
                    address, Action::Delete,
                    Some(serde_json::to_value(have).unwrap()), None,
                )),
                (Some(have), Some(want)) if have != want => {
                    changes.push(change(
                        address, Action::Update,
                        Some(serde_json::to_value(have).unwrap()),
                        Some(serde_json::to_value(want).unwrap()),
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
        let mut failed  = vec![];

        for c in &plan.changes {
            let name = c.address.strip_prefix("github_repo.").unwrap_or(&c.address);
            let res = match c.action {
                Action::Create | Action::Update | Action::Replace => {
                    let settings: RepoSettings = match &c.after {
                        Some(v) => match serde_json::from_value(v.clone()) {
                            Ok(s) => s,
                            Err(e) => {
                                failed.push(crate::FailedChange {
                                    address: c.address.clone(),
                                    action: c.action,
                                    error: format!("decode after: {e}"),
                                });
                                continue;
                            }
                        },
                        None => {
                            failed.push(crate::FailedChange {
                                address: c.address.clone(),
                                action: c.action,
                                error: "create/update without `after`".into(),
                            });
                            continue;
                        }
                    };
                    if matches!(c.action, Action::Create) {
                        self.client.create_repo(name, &settings).await
                    } else {
                        self.client.update_repo(name, &settings).await
                    }
                }
                Action::Delete => self.client.delete_repo(name).await,
                Action::NoOp   => continue,
            };
            match res {
                Ok(()) => applied.push(AppliedChange { address: c.address.clone(), action: c.action }),
                Err(e) => failed.push(crate::FailedChange {
                    address: c.address.clone(),
                    action:  c.action,
                    error:   e,
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

    fn repo(desc: &str) -> RepoSettings {
        RepoSettings {
            description:    Some(desc.into()),
            private:        false,
            default_branch: "main".into(),
            topics:         vec![],
        }
    }

    #[tokio::test]
    async fn empty_github_state() {
        let r = GithubRepoReconciler::new(MockGithubClient::new());
        let state = r.read_state().await.unwrap();
        assert_eq!(state, json!({}));
    }

    #[tokio::test]
    async fn create_plan_for_new_repo() {
        let r = GithubRepoReconciler::new(MockGithubClient::new());
        let mut desired = HashMap::new();
        desired.insert("rio".to_string(), repo("Rio cluster"));
        let config = serde_json::to_value(desired).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Create);
        assert_eq!(plan.changes[0].address, "github_repo.rio");
    }

    #[tokio::test]
    async fn apply_creates_repo_in_mock() {
        let r = GithubRepoReconciler::new(MockGithubClient::new());
        let mut desired = HashMap::new();
        desired.insert("rio".to_string(), repo("Rio"));
        let config = serde_json::to_value(desired).unwrap();
        let state  = r.read_state().await.unwrap();
        let plan   = r.compute_plan(&config, &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        assert_eq!(r.client().snapshot().get("rio").unwrap().description, Some("Rio".into()));
    }

    #[tokio::test]
    async fn update_when_description_changes() {
        let mut initial = HashMap::new();
        initial.insert("rio".to_string(), repo("old"));
        let r = GithubRepoReconciler::new(MockGithubClient::with_repos(initial));
        let mut desired = HashMap::new();
        desired.insert("rio".to_string(), repo("new"));
        let config = serde_json::to_value(desired).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.changes[0].action, Action::Update);
    }

    #[tokio::test]
    async fn topic_order_does_not_trigger_drift() {
        // Server returns topics ["a","b"]; config has ["b","a"]. Both
        // canonicalize identically; plan should be a no-op.
        let mut initial = HashMap::new();
        let mut s = repo("x");
        s.topics = vec!["a".into(), "b".into()];
        initial.insert("rio".to_string(), s.clone());
        let r = GithubRepoReconciler::new(MockGithubClient::with_repos(initial));

        let mut desired = HashMap::new();
        let mut t = s.clone();
        t.topics = vec!["b".into(), "a".into()]; // wrong order
        desired.insert("rio".to_string(), t);
        let config = serde_json::to_value(desired).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert!(plan.is_noop(), "topic order shouldn't drift, plan: {plan:?}");
    }

    #[tokio::test]
    async fn apply_failure_surfaces_as_failed_change() {
        let r = GithubRepoReconciler::new(MockGithubClient::new());
        r.client().fail_next("upstream 503");
        let mut desired = HashMap::new();
        desired.insert("rio".to_string(), repo("x"));
        let config = serde_json::to_value(desired).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();
        assert!(!outcome.fully_succeeded());
        assert_eq!(outcome.failed.len(), 1);
        assert!(outcome.failed[0].error.contains("upstream 503"));
    }
}
