//! Validate galho's EXACT live path against the real `terraform-provider-github`
//! (tfplugin6) — the provider the operator drives to create
//! `github_repository.galho`.
//!
//! `GetProviderSchema` is read-only (no credentials, no side effects), so
//! this proves the full read path end-to-end against the real target:
//! `Plugin::spawn` (go-plugin handshake + mTLS) → `GetProviderSchema`
//! (tfplugin6) → `schema::block_implied_type` on github's actual schema.
//! If `github_repository`'s implied cty type parses, galho's apply path is
//! protocol-validated against the real provider.
//!
//! Skips if no github provider is present. Populate via:
//!   cd /tmp/magma-gh-probe && tofu init   (with integrations/github required)
//! or set MAGMA_GH_WORKSPACE to such a workspace.

use std::path::PathBuf;

use magma_cty::CtyType;
use magma_plugin::provider::ProviderConn;
use magma_plugin::{Plugin, PluginSpec};

fn workspace() -> PathBuf {
    std::env::var("MAGMA_GH_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/magma-gh-probe"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn github_schema_via_real_provider() {
    // Frame-level tracing when RUST_LOG is set (h2=debug,tonic=debug) —
    // pinpoints where a body transfer stalls.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let ws = workspace();
    let binary = match magma_providers::locate_provider(&ws, "github") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP github_schema_via_real_provider: {e}");
            return;
        }
    };

    let mut plugin = Plugin::spawn(PluginSpec {
        binary,
        ..Default::default()
    })
    .await
    .expect("spawn the real github provider (go-plugin handshake + mTLS)");

    let protocol = plugin.handshake().app_protocol;
    eprintln!("github provider negotiated protocol: {protocol:?}");
    let channel = plugin.dial().await.expect("mTLS dial").clone();
    let mut conn = ProviderConn::new(channel, protocol);

    let schema = conn
        .get_schema()
        .await
        .expect("GetProviderSchema over tfplugin6 against the real provider");

    eprintln!(
        "github provider: {} managed resource schemas parsed",
        schema.resources.len()
    );
    assert!(
        schema.resources.len() > 50,
        "github provider exposes many resources (got {})",
        schema.resources.len()
    );

    let repo = schema
        .resource("github_repository")
        .expect("github_repository must be in the schema (galho's resource)");
    match repo {
        CtyType::Object(attrs) => {
            assert!(attrs.contains_key("name"), "github_repository has `name`");
            assert!(
                attrs.contains_key("visibility"),
                "github_repository has `visibility`"
            );
            assert!(
                attrs.len() > 15,
                "github_repository has a rich attribute set (got {})",
                attrs.len()
            );
            eprintln!(
                "OK: github_repository implied cty type parsed — {} attributes (galho's tfplugin6 path is live-validated)",
                attrs.len()
            );
        }
        other => panic!("github_repository should be a cty object, got {other:?}"),
    }
}
