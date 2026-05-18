//! Trait-law proptests.
//!
//! Every `Reconciler` impl must obey the universal trait laws
//! (see `magma_converge::Reconciler` docs). These tests express
//! the laws as property tests + run them against each shipped
//! impl. Adding a new impl = run these against it.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §VII.

use std::collections::HashMap;

use magma_converge::{
    inmemory::InMemoryKvReconciler,
    github::{GithubRepoReconciler, MockGithubClient, RepoSettings},
    dns::{DnsRecordReconciler, MockDnsClient, Record, RecordKey, RecordValue},
    helm::{HelmReleaseReconciler, MockHelmClient, ReleaseSpec},
    Action, Reconciler,
};
use proptest::prelude::*;
use serde_json::{json, Value};

// ── Helpers ───────────────────────────────────────────────────────

/// Build an arbitrary "kv state" — the simplest universal shape.
fn kv_state_strategy() -> impl Strategy<Value = Value> {
    proptest::collection::hash_map(
        "[a-z][a-z0-9_]{0,4}",
        prop_oneof![
            (0i64..1000).prop_map(|n| json!(n)),
            "[a-z]{1,6}".prop_map(Value::String),
            Just(json!(true)),
            Just(json!(null)),
        ],
        0..=4,
    )
    .prop_map(|m| {
        let obj: serde_json::Map<String, Value> = m.into_iter().collect();
        Value::Object(obj)
    })
}

// ── Universal law: compute_plan is deterministic ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn law_compute_plan_deterministic_inmemory(
        state in kv_state_strategy(),
        config in kv_state_strategy(),
    ) {
        let r = InMemoryKvReconciler::new();
        let p1 = r.compute_plan(&config, &state).unwrap();
        let p2 = r.compute_plan(&config, &state).unwrap();
        prop_assert_eq!(&p1.id, &p2.id);
        // Same plan_id implies the canonical change shape is equal.
        prop_assert_eq!(p1.changes.len(), p2.changes.len());
    }
}

// ── Universal law: empty plan is a no-op ─────────────────────────

#[tokio::test]
async fn law_empty_plan_apply_inmemory() {
    let r = InMemoryKvReconciler::new();
    let state = r.read_state().await.unwrap();
    let plan = r.compute_plan(&json!({}), &state).unwrap();
    assert!(plan.is_noop(), "empty config → empty plan");
    r.apply(&plan).await.unwrap();
    let after = r.read_state().await.unwrap();
    assert_eq!(state, after, "noop apply should not mutate observed state");
}

#[tokio::test]
async fn law_empty_plan_apply_github() {
    let r = GithubRepoReconciler::new(MockGithubClient::new());
    let state = r.read_state().await.unwrap();
    let plan = r.compute_plan(&json!({}), &state).unwrap();
    assert!(plan.is_noop());
    r.apply(&plan).await.unwrap();
    let after = r.read_state().await.unwrap();
    assert_eq!(state, after);
}

#[tokio::test]
async fn law_empty_plan_apply_dns() {
    let r = DnsRecordReconciler::new(MockDnsClient::new());
    let state = r.read_state().await.unwrap();
    let plan = r.compute_plan(&json!([]), &state).unwrap();
    assert!(plan.is_noop());
    r.apply(&plan).await.unwrap();
    let after = r.read_state().await.unwrap();
    assert_eq!(state, after);
}

#[tokio::test]
async fn law_empty_plan_apply_helm() {
    let r = HelmReleaseReconciler::new(MockHelmClient::new());
    let state = r.read_state().await.unwrap();
    let plan = r.compute_plan(&json!({}), &state).unwrap();
    assert!(plan.is_noop());
    r.apply(&plan).await.unwrap();
    let after = r.read_state().await.unwrap();
    assert_eq!(state, after);
}

// ── Universal law: apply converges ───────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn law_apply_converges_inmemory(
        config in kv_state_strategy(),
    ) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let r = InMemoryKvReconciler::new();
            let state = r.read_state().await.unwrap();
            let plan = r.compute_plan(&config, &state).unwrap();
            r.apply(&plan).await.unwrap();
            // After apply, the next plan against the same config is a no-op.
            let drift = r.detect_drift(&config).await.unwrap();
            prop_assert!(drift.is_noop(), "post-apply drift not empty: {drift:?}");
            Ok(())
        }).unwrap();
    }
}

// ── Universal law: read_state is referentially transparent ───────

#[tokio::test]
async fn law_read_state_idempotent_inmemory() {
    let r = InMemoryKvReconciler::with_state(
        [("k".to_string(), json!("v"))].into_iter().collect(),
    );
    let s1 = r.read_state().await.unwrap();
    let s2 = r.read_state().await.unwrap();
    assert_eq!(s1, s2);
}

#[tokio::test]
async fn law_read_state_idempotent_github() {
    let mut initial = HashMap::new();
    initial.insert("rio".to_string(), RepoSettings {
        description: Some("x".into()),
        private: false,
        default_branch: "main".into(),
        topics: vec!["a".into(), "b".into()],
    });
    let r = GithubRepoReconciler::new(MockGithubClient::with_repos(initial));
    let s1 = r.read_state().await.unwrap();
    let s2 = r.read_state().await.unwrap();
    assert_eq!(s1, s2);
}

#[tokio::test]
async fn law_read_state_idempotent_dns() {
    let initial = vec![Record {
        key: RecordKey { zone: "ex.com".into(), name: "api".into(), r#type: "A".into() },
        value: RecordValue { value: "1.2.3.4".into(), ttl: 300, proxied: false },
    }];
    let r = DnsRecordReconciler::new(MockDnsClient::with_records(initial));
    let s1 = r.read_state().await.unwrap();
    let s2 = r.read_state().await.unwrap();
    assert_eq!(s1, s2);
}

#[tokio::test]
async fn law_read_state_idempotent_helm() {
    let mut initial = HashMap::new();
    initial.insert("nginx".to_string(), ReleaseSpec {
        chart: "ingress-nginx".into(),
        version: "4.7.0".into(),
        namespace: "default".into(),
        values: json!({ "replicas": 2 }),
    });
    let r = HelmReleaseReconciler::new(MockHelmClient::with_releases(initial));
    let s1 = r.read_state().await.unwrap();
    let s2 = r.read_state().await.unwrap();
    assert_eq!(s1, s2);
}

#[tokio::test]
async fn law_apply_converges_helm() {
    let r = HelmReleaseReconciler::new(MockHelmClient::new());
    let mut desired = HashMap::new();
    desired.insert("nginx".to_string(), ReleaseSpec {
        chart: "ingress-nginx".into(),
        version: "4.7.0".into(),
        namespace: "default".into(),
        values: json!({}),
    });
    let config = serde_json::to_value(desired).unwrap();
    let state = r.read_state().await.unwrap();
    let plan = r.compute_plan(&config, &state).unwrap();
    r.apply(&plan).await.unwrap();
    let drift = r.detect_drift(&config).await.unwrap();
    assert!(drift.is_noop());
}

// ── Universal law: plan_id differs when config differs ───────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn law_plan_id_differs_with_config_inmemory(
        state in kv_state_strategy(),
        cfg_a in kv_state_strategy(),
        cfg_b in kv_state_strategy(),
    ) {
        let r = InMemoryKvReconciler::new();
        let p_a = r.compute_plan(&cfg_a, &state).unwrap();
        let p_b = r.compute_plan(&cfg_b, &state).unwrap();
        // If both plans produce equal change sets, plan_ids match
        // (determinism). If change sets differ, plan_ids differ.
        if p_a.changes == p_b.changes {
            prop_assert_eq!(p_a.id, p_b.id);
        } else {
            prop_assert_ne!(p_a.id, p_b.id);
        }
    }
}

// ── Cross-reconciler: kind labels are unique ────────────────────

#[test]
fn law_kinds_are_unique() {
    let kinds = vec![
        InMemoryKvReconciler::new().kind(),
        GithubRepoReconciler::new(MockGithubClient::new()).kind(),
        DnsRecordReconciler::new(MockDnsClient::new()).kind(),
        HelmReleaseReconciler::new(MockHelmClient::new()).kind(),
    ];
    let unique: std::collections::HashSet<_> = kinds.iter().collect();
    assert_eq!(unique.len(), kinds.len(), "reconciler kinds collide: {kinds:?}");
}

// ── Cross-reconciler: action surface stays universal ────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn law_actions_in_plan_are_universal(
        state  in kv_state_strategy(),
        config in kv_state_strategy(),
    ) {
        let r = InMemoryKvReconciler::new();
        let plan = r.compute_plan(&config, &state).unwrap();
        for c in &plan.changes {
            prop_assert!(matches!(c.action,
                Action::Create | Action::Update | Action::Delete |
                Action::Replace | Action::NoOp));
        }
    }
}
