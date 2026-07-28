//! End-to-end proof that a ForceNew attribute change applies as an
//! orchestrated destroy+create, never a single malformed
//! `ApplyResourceChange` call — over the REAL tfplugin6 wire protocol
//! against a spawned provider subprocess (not a unit-level fake).
//!
//! Drives the SAME path a real cloud apply uses: `run_plan_with_providers`
//! → `Registry::spawn` → `dial_configured_provider` →
//! `ProviderConn::plan_resource_change` (now decoding `requires_replace`)
//! → `magma-apply::engine::apply_one`'s `is_replace` branch → `apply_replace`
//! (destroy, re-plan from null, create — two `ApplyResourceChange` RPCs,
//! never one).
//!
//! `mock_provider`'s `mock_replace_resource` resource type treats
//! `immutable_field` as ForceNew: `plan_resource_change` reports it in
//! `requires_replace` when a prior instance's value differs from the
//! proposed one, and `apply_resource_change` returns an ERROR diagnostic
//! if it ever receives a single call whose `prior_state` and
//! `planned_state` disagree on `immutable_field` — exactly what a real
//! SDKv2/framework provider does when handed a malformed in-place-update
//! request for an immutable attribute.
//!
//! `force_new_attribute_change_applies_as_destroy_then_create` would have
//! FAILED before the fix: the pre-fix `apply_one` catch-all sent exactly
//! one such malformed call for every action alike (Create / Update /
//! Replace / CreateThenDelete / DeleteThenCreate / Read), so this change
//! would have landed in `outcome.failed`, not `outcome.applied`.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use magma_apply::engine::{ApplyContext, run_plan_with_providers};
use magma_cty::DynamicValue;
use magma_plugin::provider::ProviderConn;
use magma_plugin::{Plugin, PluginSpec};
use magma_types::{
    Action, ChangeReason, ModulePath, Plan, PlanId, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State,
};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

/// A workspace whose `.terraform/providers/` holds ONLY the mock binary,
/// named so `magma_providers::locate_provider(_, "mock")` finds it —
/// mirrors real `tofu init`'s output layout (`terraform-provider-<name>`).
fn workspace_with_mock_provider() -> tempfile::TempDir {
    let td = tempfile::tempdir().expect("tempdir");
    let providers_dir = td.path().join(".terraform").join("providers");
    fs::create_dir_all(&providers_dir).expect("mkdir providers dir");
    let dest = providers_dir.join("terraform-provider-mock");
    fs::copy(mock_provider_binary(), &dest).expect("copy mock_provider binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).expect("chmod +x");
    }
    td
}

fn replace_change(before_field: &str, after_field: &str) -> ResourceChange {
    ResourceChange {
        address: ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("mock_replace_resource".to_string()),
            name: "under_test".to_string(),
            key: None,
        },
        // magma-plan's M0 config-subset heuristic classifies EVERY
        // in-both attribute drift as `Update` (see magma-plan's module
        // docs — it has no schema access, so it cannot know
        // `immutable_field` is ForceNew). This is the EXACT shape a
        // ForceNew attribute change plans as today; the fix must still
        // route it to destroy+create at apply time, driven purely by the
        // provider's own `requires_replace` signal.
        action: Action::Update,
        before: Some(serde_json::json!({
            "id": "existing-id",
            "name": "stable-name",
            "immutable_field": before_field,
        })),
        after: Some(serde_json::json!({
            "name": "stable-name",
            "immutable_field": after_field,
        })),
        reasons: vec![ChangeReason::AttributeDrift],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_new_attribute_change_applies_as_destroy_then_create() {
    let ws = workspace_with_mock_provider();
    let plan = Plan {
        id: PlanId([0u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: PathBuf::new(),
        variables: Default::default(),
        resource_changes: vec![replace_change("old-value", "new-value")],
        output_changes: Vec::new(),
        observation: magma_types::Observation::unrefreshed(),
    };
    let mut state = State {
        version: 4,
        terraform_version: "1.9.0".to_string(),
        serial: 0,
        lineage: uuid::Uuid::nil(),
        outputs: Default::default(),
        resources: Vec::new(),
    };
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let outcome = run_plan_with_providers(&plan, &mut state, &ctx).await;

    assert!(
        outcome.failed.is_empty(),
        "a ForceNew attribute change must apply via orchestrated \
         destroy+create, never the single malformed ApplyResourceChange \
         call a real provider hard-fails on: {:?}",
        outcome.failed
    );
    assert_eq!(outcome.applied.len(), 1, "exactly one change applied");
    let applied = &outcome.applied[0];
    assert_eq!(
        applied.action,
        Action::DeleteThenCreate,
        "the recorded action must reflect what ACTUALLY happened \
         (destroy+create), not the incoming plan's Update classification"
    );
    let new_attrs = applied.after.as_ref().expect("replacement carries new state");
    assert_eq!(
        new_attrs.get("immutable_field").and_then(|v| v.as_str()),
        Some("new-value"),
        "the replacement instance carries the NEW immutable_field value"
    );

    assert_eq!(
        state.resources.len(),
        1,
        "state carries exactly the replacement instance"
    );
    let stored = &state.resources[0].instances[0].attributes;
    assert_eq!(
        stored.get("immutable_field").and_then(|v| v.as_str()),
        Some("new-value"),
        "state was not left holding the stale pre-replace value"
    );
}

/// Regression guard for the PRE-fix behavior: proves the mock provider's
/// synthetic ForceNew rejection is real (not vacuously always-passing) by
/// driving the malformed single-call shape directly against the wire
/// protocol — the exact `ApplyResourceChange(prior_state=old,
/// planned_state=already-replacement-shaped)` request the old `apply_one`
/// catch-all sent for every action alike. If the mock ever stops failing
/// this, `force_new_attribute_change_applies_as_destroy_then_create`
/// above would stop proving anything (it would pass whether or not the
/// fix routes around the malformed call).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_provider_rejects_the_pre_fix_malformed_single_call_replace() {
    let spec = PluginSpec {
        binary: mock_provider_binary(),
        kill_grace: Duration::from_secs(1),
        secure: false,
        ..PluginSpec::default()
    };
    let mut plugin = Plugin::spawn(spec).await.expect("spawn handshake");
    let protocol = plugin.handshake().app_protocol;
    let channel = plugin.dial().await.expect("dial gRPC").clone();
    let mut conn = ProviderConn::new(channel, protocol);
    let schema = conn.get_schema().await.expect("GetProviderSchema");
    let implied = schema
        .resource("mock_replace_resource")
        .expect("mock_replace_resource schema present")
        .clone();
    let config_dv = DynamicValue::from_json(&serde_json::json!({}), &schema.provider_config)
        .expect("encode empty provider config");
    conn.configure(&config_dv, "1.9.0")
        .await
        .expect("ConfigureProvider");

    let prior = DynamicValue::from_json(
        &serde_json::json!({"id": "x", "name": "n", "immutable_field": "old"}),
        &implied,
    )
    .expect("encode prior");
    let planned = DynamicValue::from_json(
        &serde_json::json!({"id": "x", "name": "n", "immutable_field": "new"}),
        &implied,
    )
    .expect("encode planned");

    let result = conn
        .apply_resource_change("mock_replace_resource", &prior, &planned, &planned)
        .await;
    assert!(
        result.is_err(),
        "the mock's synthetic ForceNew guard must reject a single-call \
         (prior_state.immutable_field != planned_state.immutable_field) \
         request — if this starts passing, the destroy-then-create test \
         above no longer proves the fix routes around the malformed call"
    );
}
