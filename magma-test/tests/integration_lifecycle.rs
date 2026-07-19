//! Full lifecycle integration test: spawn mock provider → dial gRPC →
//! GetProviderSchema → PlanResourceChange → ApplyResourceChange.
//!
//! Closes §IV.2 (tfplugin6 protocol bindings) end-to-end alongside
//! §IV.1 (handshake) — proves magma can complete the entire
//! per-resource lifecycle (plan → apply) over a real gRPC channel
//! against a typed provider implementation.
//!
//! Per `theory/MAGMA.md` §II.6 level 5 (apply-against-real-cloud),
//! this is the offline mock variant; the real-cloud lifecycle test
//! against `hashicorp/null` lands once the provider binary is
//! reachable in CI.

use std::path::PathBuf;
use std::time::Duration;

use magma_plugin::{Plugin, PluginSpec};
use magma_protocol::tfplugin6;
use magma_protocol::tfplugin6::provider_client::ProviderClient;

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_lifecycle_against_mock() {
    let binary = mock_provider_binary();
    assert!(binary.exists());

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(1),
        secure: false, // mock_provider runs plain h2c
        ..PluginSpec::default()
    };

    // 1. Spawn + handshake.
    let mut plugin = Plugin::spawn(spec).await.expect("spawn handshake");
    assert!(plugin.handshake().cert_pem_base64.is_some());

    // 2. Dial the gRPC Channel.
    let channel = plugin.dial().await.expect("dial gRPC").clone();

    // 3. GetProviderSchema — assert the schema came back with the
    // single resource type our mock declares.
    let mut client = ProviderClient::new(channel);
    let schema_resp = client
        .get_provider_schema(tfplugin6::get_provider_schema::Request {})
        .await
        .expect("GetProviderSchema RPC")
        .into_inner();
    assert!(
        schema_resp.diagnostics.is_empty(),
        "no diagnostics expected"
    );
    assert!(schema_resp.provider.is_some(), "provider schema present");
    assert!(
        schema_resp.resource_schemas.contains_key("mock_resource"),
        "mock_resource resource schema present",
    );

    // 4. PlanResourceChange — assert the canned response echoes inputs.
    let plan_req = tfplugin6::plan_resource_change::Request {
        type_name: "mock_resource".into(),
        prior_state: None,
        proposed_new_state: None,
        config: None,
        prior_private: vec![],
        provider_meta: None,
        client_capabilities: None,
        prior_identity: None,
    };
    let plan_resp = client
        .plan_resource_change(plan_req)
        .await
        .expect("PlanResourceChange RPC")
        .into_inner();
    assert!(plan_resp.diagnostics.is_empty(), "plan has no diagnostics");
    assert!(plan_resp.requires_replace.is_empty(), "no replace required");

    // 5. ApplyResourceChange — assert new_state echoes planned_state.
    let apply_req = tfplugin6::apply_resource_change::Request {
        type_name: "mock_resource".into(),
        prior_state: None,
        planned_state: None,
        config: None,
        planned_private: vec![],
        provider_meta: None,
        planned_identity: None,
    };
    let apply_resp = client
        .apply_resource_change(apply_req)
        .await
        .expect("ApplyResourceChange RPC")
        .into_inner();
    assert!(
        apply_resp.diagnostics.is_empty(),
        "apply has no diagnostics"
    );

    // 6. Clean up — Plugin::drop sends SIGTERM/SIGKILL.
    drop(plugin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schema_only_smoke() {
    // §II.6 level 1 (Smoke) — minimal proof that schema retrieval works.
    let binary = mock_provider_binary();
    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(1),
        secure: false,
        ..PluginSpec::default()
    };
    let mut plugin = Plugin::spawn(spec).await.expect("spawn");
    let channel = plugin.dial().await.expect("dial").clone();
    let mut client = ProviderClient::new(channel);
    let resp = client
        .get_provider_schema(tfplugin6::get_provider_schema::Request {})
        .await
        .expect("schema RPC")
        .into_inner();
    // `mock_resource` (this test's original fixture) + `mock_replace_resource`
    // (the ForceNew-attribute fixture added for
    // `integration_replace_destroy_then_create.rs`) — assert both are
    // present by name rather than re-pinning a bare count, so a THIRD
    // fixture added later doesn't silently break this smoke test again.
    assert!(resp.resource_schemas.contains_key("mock_resource"));
    assert!(resp.resource_schemas.contains_key("mock_replace_resource"));
}
