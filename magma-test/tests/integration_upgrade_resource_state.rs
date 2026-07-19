//! Integration law battery for `ProviderConn::upgrade_resource_state` —
//! the RPC magma-apply must call before decoding a `StateInstance` whose
//! stored `schema_version` is older than the provider's CURRENT declared
//! schema version. Before this fix, `upgrade_resource_state` had ZERO
//! client-side implementation anywhere in the workspace (only
//! `mock_provider`'s SERVER stub existed, itself returning
//! `Status::unimplemented`), and `ProviderSchema` silently discarded the
//! provider's declared `Schema.version` while parsing `GetProviderSchema` —
//! so magma could never detect a schema mismatch, and every production
//! write path stamped `schema_version: 0` regardless of the provider's
//! real schema.
//!
//! Drives the REAL wire path against `mock_provider`, whose `mock_resource`
//! type declares schema version 1 and — per its own doc comment — used to
//! call the same attribute `legacy_owner` before that bump (now named
//! `imported_by`) — exactly the class of schema evolution
//! `UpgradeResourceState` exists to migrate forward.

use std::path::PathBuf;
use std::time::Duration;

use magma_apply::engine::{ApplyContext, refresh_state};
use magma_plugin::provider::ProviderConn;
use magma_plugin::{Plugin, PluginSpec};
use magma_state::empty_state;
use magma_types::{
    InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId,
    StateInstance, StateResource,
};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

/// A fake workspace whose `.terraform/providers/` holds the mock provider
/// binary named `terraform-provider-mock` — exactly how a real
/// `github`/`cloudflare`/`aws` provider is laid out after `tofu init`, per
/// `magma_providers::locate_provider`'s doc. Mirrors
/// `integration_import_resource_state.rs`'s identically-named helper (kept
/// local per that file's own convention — each integration test file is
/// self-contained).
fn configured_provider_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let providers_dir = dir.path().join(".terraform").join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir .terraform/providers");
    let dest = providers_dir.join("terraform-provider-mock");
    std::fs::copy(mock_provider_binary(), &dest).expect("copy mock_provider binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest)
            .expect("stat copied binary")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest, perms).expect("chmod copied binary +x");
    }
    dir
}

async fn spawn_conn() -> (Plugin, ProviderConn) {
    let spec = PluginSpec {
        binary: mock_provider_binary(),
        kill_grace: Duration::from_secs(1),
        secure: false, // mock_provider runs plain h2c
        ..PluginSpec::default()
    };
    let mut plugin = Plugin::spawn(spec).await.expect("spawn mock provider");
    let protocol = plugin.handshake().app_protocol;
    let channel = plugin.dial().await.expect("dial gRPC").clone();
    (plugin, ProviderConn::new(channel, protocol))
}

// ── Law 1: the provider's declared schema version survives parsing ─────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_schema_surfaces_the_real_declared_version() {
    let (_plugin, mut conn) = spawn_conn().await;
    let schema = conn.get_schema().await.expect("GetProviderSchema RPC");

    // Before this fix, `ProviderSchema` had no `resource_versions` field at
    // all — `GetProviderSchema`'s per-resource `Schema.version` was parsed
    // and immediately discarded (only `Schema.block` survived). A type
    // magma has never seen must read as version 0 (Terraform's own
    // convention for "unversioned"), never panic or silently guess.
    assert_eq!(
        schema.resource_version("mock_resource"),
        1,
        "the provider's declared schema version must be captured, not silently dropped",
    );
    assert_eq!(schema.resource_version_u64("mock_resource"), 1);
    assert_eq!(
        schema.resource_version("nonexistent_type"),
        0,
        "an unknown type must read as version 0, never panic or guess",
    );
}

// ── Law 2: UpgradeResourceState migrates a stale v0-shaped instance ────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrade_resource_state_migrates_a_v0_shaped_instance_to_current_schema() {
    let (_plugin, mut conn) = spawn_conn().await;
    let schema = conn.get_schema().await.expect("GetProviderSchema RPC");
    let implied = schema
        .resource("mock_resource")
        .expect("mock_resource schema present")
        .clone();

    // A `StateInstance` persisted under the OLD (v0) schema — the field
    // was named `legacy_owner` before the provider's v1 rename.
    let stored_v0_json = serde_json::to_vec(&serde_json::json!({
        "id": "res-1",
        "name": "res-1",
        "legacy_owner": "old-team",
    }))
    .expect("encode stored v0 JSON");

    let upgraded = conn
        .upgrade_resource_state("mock_resource", 0, &stored_v0_json)
        .await
        .expect("UpgradeResourceState RPC");
    let attrs = upgraded
        .to_json(&implied)
        .expect("decode the upgraded state against the CURRENT (v1) schema");

    // The migrated field lands under its NEW v1 name; the stale v0 name is
    // gone. Decoding the raw v0 JSON directly against the v1 implied type
    // (the ONLY thing magma could do before this fix — there was no
    // upgrade_resource_state to call) drops `legacy_owner` on the floor —
    // an attribute the current schema simply doesn't declare — silently
    // losing the migrated data instead of ever encountering it.
    assert_eq!(attrs["imported_by"], "old-team");
    assert_eq!(attrs["id"], "res-1");
    assert!(
        attrs.get("legacy_owner").is_none() || attrs["legacy_owner"].is_null(),
        "the stale v0 field name must not survive the upgrade: {attrs:?}",
    );

    // Prove the "before this fix" claim directly: decoding the SAME raw
    // v0 JSON straight against the current implied type — skipping
    // UpgradeResourceState entirely, the pre-fix code path — never
    // recovers `imported_by` at all.
    let direct = magma_cty::DynamicValue::from_json(
        &serde_json::from_slice(&stored_v0_json).unwrap(),
        &implied,
    )
    .expect("direct decode (unknown attrs merely ignored, not a hard error)")
    .to_json(&implied)
    .expect("decode back to JSON");
    assert!(
        direct.get("imported_by").is_none() || direct["imported_by"].is_null(),
        "direct decode (no UpgradeResourceState) must NOT recover the migrated \
         field — proving the RPC is load-bearing, not redundant: {direct:?}",
    );
}

// ── Law 3: UpgradeResourceState is a safe no-op already-at-current ─────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrade_resource_state_is_a_safe_noop_at_current_version() {
    let (_plugin, mut conn) = spawn_conn().await;
    let schema = conn.get_schema().await.expect("GetProviderSchema RPC");
    let implied = schema
        .resource("mock_resource")
        .expect("schema present")
        .clone();

    let current_json = serde_json::to_vec(&serde_json::json!({
        "id": "res-2",
        "name": "res-2",
        "imported_by": "current-team",
    }))
    .expect("encode current-version JSON");

    let upgraded = conn
        .upgrade_resource_state("mock_resource", 1, &current_json)
        .await
        .expect("UpgradeResourceState RPC at the current version");
    let attrs = upgraded.to_json(&implied).expect("decode");
    assert_eq!(attrs["imported_by"], "current-team");
    assert_eq!(attrs["id"], "res-2");
}

// ── Law 4: `engine::refresh_state` wires the upgrade in end-to-end ─────
//
// The three laws above prove the client-side RPC wrapper + schema-version
// capture work in isolation. THIS is the load-bearing proof: magma-apply's
// REAL production `refresh_state` — the function every refresh/plan cycle
// calls — must itself detect a stale `schema_version`, call
// `UpgradeResourceState`, and persist BOTH the migrated attributes and the
// bumped `schema_version`. This is exactly the scenario the gap allowed:
// a `StateInstance` written before this fix (every production write path
// hardcoded `schema_version: 0`) against a provider whose real schema has
// since moved past v0.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_state_migrates_a_stale_schema_version_end_to_end() {
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());

    let addr = ResourceAddress {
        module: ModulePath::root(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId("mock_resource".into()),
        name: "legacy".into(),
        key: None,
    };
    let mut state = empty_state();
    state.resources.push(StateResource {
        address: addr.clone(),
        provider: ProviderReference {
            source: "mock/mock".into(),
            name: "mock".into(),
            alias: None,
        },
        instances: vec![StateInstance {
            // Stored under the OLD (v0) schema — pre-fix, EVERY
            // production write path hardcoded schema_version: 0
            // regardless of the provider's real declared version, so
            // this is exactly the state a pre-fix apply would have
            // left behind.
            schema_version: 0,
            attributes: serde_json::json!({
                "id": "res-1",
                "name": "res-1",
                "legacy_owner": "old-team",
            }),
            private: vec![],
            dependencies: vec![],
            status: InstanceStatus::Ready,
        }],
    });

    let report = refresh_state(&mut state, &ctx).await;

    assert_eq!(
        report.kept_on_error, 0,
        "the migration must succeed cleanly, not fall back to kept_on_error: {report:?}",
    );
    assert_eq!(report.refreshed, 1, "{report:?}");
    assert_eq!(state.resources.len(), 1);
    let inst = &state.resources[0].instances[0];
    assert_eq!(
        inst.schema_version, 1,
        "the stored schema_version must be bumped to the provider's CURRENT \
         declared version — leaving it at 0 forever (the pre-fix behavior) \
         would re-trigger the same migration on every future cycle and never \
         converge to 'checked'",
    );
    assert_eq!(
        inst.attributes["imported_by"], "old-team",
        "the v0-shaped raw attributes must be migrated via UpgradeResourceState \
         BEFORE ReadResource decodes them — this is the exact failure mode the \
         gap named: 'malformed DynamicValue marshaling ... whenever a \
         provider's resource schema evolves'",
    );
    assert!(
        inst.attributes.get("legacy_owner").is_none()
            || inst.attributes["legacy_owner"].is_null(),
        "the stale v0 field name must not survive: {:?}",
        inst.attributes,
    );
}
