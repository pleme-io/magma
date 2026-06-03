//! ProviderRegistry end-to-end against REAL providers.
//!
//! Proves the registry's RPC surface materializes a resource through a
//! real provider: connect → configure → plan_create → apply_create →
//! decode msgpack new_state into json with the provider-filled computed
//! `id`. Uses the vendored null provider (no credentials). Also proves
//! plugin-cache resolution + protocol dispatch against the real github
//! provider (the rio target).
//!
//! Both tests skip-with-print when their provider binary is absent, so
//! a bare CI host stays green.

use std::path::PathBuf;

use magma_providers::ProviderRegistry;
use serde_json::json;

fn null_fixture() -> Option<PathBuf> {
    for c in [
        "../magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
        "magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p.canonicalize().unwrap_or(p));
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_create_lifecycle_null() {
    let Some(binary) = null_fixture() else {
        eprintln!("skip: null provider fixture missing");
        return;
    };

    let reg = ProviderRegistry::from_default_cache();
    let conn = reg
        .connect_binary("hashicorp/null", binary)
        .await
        .expect("connect null");

    // null takes no provider config.
    conn.configure(&json!({})).await.expect("configure");

    let config = json!({ "triggers": { "magma": "v1" }, "id": null });
    let planned = conn
        .plan_create("null_resource", &config)
        .await
        .expect("plan_create");
    let new_state = conn
        .apply_create("null_resource", &planned, &config)
        .await
        .expect("apply_create");

    eprintln!("registry-created null_resource state: {new_state}");
    // The provider FILLED the computed `id` — proof a real create ran
    // through the provider RPC and the msgpack response decoded to json.
    assert!(
        new_state.get("id").map(|v| !v.is_null()).unwrap_or(false),
        "provider should fill computed `id`, got: {new_state}",
    );
    assert_eq!(new_state["triggers"]["magma"], json!("v1"));

    // Connection is cached — second connect returns without re-spawning.
    let again = reg.connect_binary("hashicorp/null", PathBuf::from("/ignored")).await;
    assert!(again.is_ok(), "cached connection should resolve without the binary");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_resolves_and_connects_github_from_cache() {
    let reg = ProviderRegistry::from_default_cache();
    // Resolve from the real terraform plugin cache.
    let Ok(conn) = reg.connect("integrations/github").await else {
        eprintln!("skip: integrations/github not in ~/.terraform.d/plugin-cache");
        return;
    };
    // github v6.x is an SDKv2 provider → protocol v5.
    assert_eq!(conn.protocol(), magma_protocol::PluginProtocol::V5);
    let types = conn.resource_types().await.expect("resource_types");
    assert!(
        types.iter().any(|t| t == "github_repository"),
        "github_repository present (got {} types)",
        types.len(),
    );
}
