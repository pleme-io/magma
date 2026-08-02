//! End-to-end verification of the provider-backed apply engine against a
//! REAL tfplugin6 provider — `terraform-provider-random`.
//!
//! `random_id` applies with no credentials + no external API, so this
//! exercises the entire live path — `Plugin::spawn` (go-plugin handshake,
//! magic cookie, mTLS) → `ConfigureProvider` → `PlanResourceChange` →
//! `ApplyResourceChange` → fold `new_state` into magma `State` — without
//! touching any cloud. If this creates a `random_id` with a generated
//! value, the apply stack is proven against a real provider, de-risking
//! the operator deploy.
//!
//! Skips gracefully if no `random` provider binary is found (CI without
//! a `.terraform/providers` tree), so it never fails a clean checkout.

use std::path::PathBuf;

use magma_apply::engine::{ApplyContext, run_plan_with_providers};
use std::collections::HashMap;

use magma_types::{
    Action, ModulePath, Plan, PlanId, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State,
};

/// A workspace that has run `init` and thus has a `random` provider on
/// disk. Overridable via env for other checkouts/CI.
fn workspace() -> PathBuf {
    std::env::var("MAGMA_TEST_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(
                "/Users/drzzln/code/github/pleme-io/pangea-gems/pangea/test_infrastructure",
            )
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn random_id_applies_via_real_provider() {
    let ws = workspace();
    if magma_providers::locate_provider(&ws, "random").is_err() {
        eprintln!(
            "SKIP real_provider_apply: no `random` provider under {} (run `tofu init` there, or set MAGMA_TEST_WORKSPACE)",
            ws.display()
        );
        return;
    }

    // Plan: create random_id.test with byte_length = 8.
    let change = ResourceChange {
        address: ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("random_id".to_string()),
            name: "test".to_string(),
            key: None,
        },
        action: Action::Create,
        before: None,
        after: Some(serde_json::json!({ "byte_length": 8 })),
        reasons: Vec::new(),
        meta: Default::default(),
    };
    let plan = Plan {
        id: PlanId([0u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: PathBuf::new(),
        variables: HashMap::new(),
        resource_changes: vec![change],
        output_changes: Vec::new(),
        observation: magma_types::Observation::unrefreshed(),
    };

    let mut state = State {
        version: 4,
        terraform_version: "1.9.0".to_string(),
        serial: 0,
        lineage: uuid::Uuid::nil(),
        outputs: HashMap::new(),
        resources: Vec::new(),
    };
    let ctx = ApplyContext::new(ws);

    let outcome = run_plan_with_providers(&plan, &mut state, &ctx).await;

    assert!(
        outcome.failed.is_empty(),
        "apply produced failures (the engine drove a real provider but it errored): {:?}",
        outcome.failed
    );
    assert_eq!(outcome.applied.len(), 1, "exactly one change applied");
    assert_eq!(state.resources.len(), 1, "random_id is now in state");

    let attrs = &state.resources[0].instances[0].attributes;
    // random_id computes hex / dec / b64_* / id at apply time — proof the
    // provider actually ran ApplyResourceChange (not a structural no-op).
    let hex = attrs.get("hex").and_then(|v| v.as_str());
    assert!(
        hex.map(|h| !h.is_empty()).unwrap_or(false),
        "provider-computed `hex` must be present + non-empty (full apply round-trip): {attrs}"
    );
    // byte_length=8 → 16 hex chars.
    assert_eq!(hex.unwrap().len(), 16, "8 bytes → 16 hex chars: {attrs}");
}
