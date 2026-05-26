//! Integration test: every concrete Reconciler in magma-converge
//! obeys the five universal Reconciler laws.
//!
//! Each reconciler is wired up with its in-process Mock client (or
//! shared `InMemoryBackend` for terraform), then passed through
//! `assert_all_laws`. A failure here means a Reconciler impl drifted
//! away from the universal contract — the substrate's promise that
//! "any Reconciler is interchangeable with any other Reconciler" is
//! now broken for that impl.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §VII. Per the Compounding
//! Directive: contract testing happens once, in one place
//! (magma-test-laws), and is consumed by every impl.

use std::collections::HashMap;
use std::sync::Arc;

use magma_test_laws::assert_all_laws;

use magma_backend::InMemoryBackend;
use magma_converge::Reconciler;
use magma_converge::dns::{DnsRecordReconciler, MockDnsClient, Record, RecordKey, RecordValue};
use magma_converge::github::{GithubRepoReconciler, MockGithubClient, RepoSettings};
use magma_converge::helm::{HelmReleaseReconciler, MockHelmClient, ReleaseSpec};
use magma_converge::terraform::TerraformReconciler;
use magma_converge::vault::{MockVaultClient, PolicyBody, VaultPolicyReconciler};
use serde_json::{Value, json};

// ── Helpers ────────────────────────────────────────────────────────

fn helm_config(version: &str) -> Value {
    let mut m: HashMap<String, ReleaseSpec> = HashMap::new();
    m.insert(
        "nginx".into(),
        ReleaseSpec {
            chart: "ingress-nginx/ingress-nginx".into(),
            version: version.into(),
            namespace: "ingress".into(),
            values: json!({"replicaCount": 2}),
        },
    );
    serde_json::to_value(m).unwrap()
}

fn dns_config(value: &str) -> Value {
    serde_json::to_value(vec![Record {
        key: RecordKey {
            zone: "ex.com".into(),
            name: "api".into(),
            r#type: "A".into(),
        },
        value: RecordValue {
            value: value.into(),
            ttl: 300,
            proxied: false,
        },
    }])
    .unwrap()
}

fn vault_config(version: &str) -> Value {
    let mut m: HashMap<String, PolicyBody> = HashMap::new();
    m.insert(
        "ro".into(),
        PolicyBody {
            version: version.into(),
            rules: json!({"path": {"secret/*": {"capabilities": ["read"]}}}),
        },
    );
    serde_json::to_value(m).unwrap()
}

fn github_config(description: &str) -> Value {
    let mut m: HashMap<String, RepoSettings> = HashMap::new();
    m.insert(
        "rio".into(),
        RepoSettings {
            description: Some(description.into()),
            private: false,
            default_branch: "main".into(),
            topics: vec!["k8s".into(), "platform".into()],
        },
    );
    serde_json::to_value(m).unwrap()
}

fn terraform_config(role_name: &str) -> Value {
    json!({
        "provider": { "aws": { "region": "us-east-1" } },
        "resource": { "aws_iam_role": { "node": { "name": role_name } } },
    })
}

// ── The law battery, applied to each concrete impl ───────────────────

#[tokio::test]
async fn helm_reconciler_obeys_laws() {
    let r = HelmReleaseReconciler::new(MockHelmClient::new());
    let initial_state = r.read_state().await.unwrap();
    assert_all_laws(
        &r,
        &helm_config("4.7.0"),
        &helm_config("4.8.0"),
        &initial_state,
        &serde_json::to_value(HashMap::<String, ReleaseSpec>::new()).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn dns_reconciler_obeys_laws() {
    let r = DnsRecordReconciler::new(MockDnsClient::new());
    let initial_state = r.read_state().await.unwrap();
    assert_all_laws(
        &r,
        &dns_config("1.1.1.1"),
        &dns_config("2.2.2.2"),
        &initial_state,
        &serde_json::to_value(Vec::<Record>::new()).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn vault_reconciler_obeys_laws() {
    let r = VaultPolicyReconciler::new(MockVaultClient::new());
    let initial_state = r.read_state().await.unwrap();
    assert_all_laws(
        &r,
        &vault_config("v1"),
        &vault_config("v2"),
        &initial_state,
        &serde_json::to_value(HashMap::<String, PolicyBody>::new()).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn github_reconciler_obeys_laws() {
    let r = GithubRepoReconciler::new(MockGithubClient::new());
    let initial_state = r.read_state().await.unwrap();
    assert_all_laws(
        &r,
        &github_config("first"),
        &github_config("second"),
        &initial_state,
        &serde_json::to_value(HashMap::<String, RepoSettings>::new()).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn terraform_reconciler_obeys_laws() {
    let r = TerraformReconciler::new(Arc::new(InMemoryBackend::new()));
    let initial_state = r.read_state().await.unwrap();
    assert_all_laws(
        &r,
        &terraform_config("alpha-role"),
        &terraform_config("beta-role"),
        &initial_state,
        &json!({"provider": {}, "resource": {}}),
    )
    .await;
}
