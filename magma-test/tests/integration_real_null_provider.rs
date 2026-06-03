//! Real-provider lifecycle test against `hashicorp/null v3.2.4`.
//!
//! Closes §II.6 level 1 (smoke) + level 2 (schema-diff seed) for a
//! Tier 1 provider — proves magma can complete the handshake, dial
//! gRPC, fetch the schema, and exercise plan/apply against a real
//! Terraform-ecosystem provider binary (not a mock).
//!
//! The provider binary is downloaded into
//! `magma-test/fixtures/providers/` once via
//!
//!   curl -fsSL https://releases.hashicorp.com/terraform-provider-null/3.2.4/terraform-provider-null_3.2.4_darwin_arm64.zip
//!     -o /tmp/null.zip && unzip /tmp/null.zip -d magma-test/fixtures/providers/
//!
//! Tests skip-with-print when the binary is absent (Linux CI without
//! the download step, fresh checkouts, etc.). The full automated
//! download lands in M0.x via `magma-providers` registry client.

use std::path::PathBuf;
use std::time::Duration;

use magma_plugin::{Plugin, PluginSpec};
use magma_protocol::tfplugin6;
use magma_protocol::tfplugin6::provider_client::ProviderClient;

/// Locate the vendored null-provider binary. Returns `None` if absent
/// (tests skip-with-print rather than fail in that case).
fn locate_null_provider() -> Option<PathBuf> {
    let candidates = [
        "magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
        "../magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path.canonicalize().unwrap_or(path));
        }
    }
    // Look relative to CARGO_MANIFEST_DIR for the magma-test crate.
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest_dir)
            .join("fixtures/providers/terraform-provider-null_v3.2.4_x5");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Locate the github provider binary in the terraform plugin cache
/// (`~/.terraform.d/plugin-cache/<registry>/integrations/github/<ver>/<os_arch>/
/// terraform-provider-github_*`). This is the resolver shape the real
/// `magma-providers::ProviderRegistry` formalizes; here it proves the v6
/// client path against the ACTUAL rio target provider (github is v6,
/// SDKv2-framework-mux), not just the v5 null provider. GetProviderSchema
/// needs no credentials.
fn locate_cached_github_provider() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let cache = PathBuf::from(home).join(".terraform.d/plugin-cache");
    // <registry>/integrations/github/<version>/<os_arch>/terraform-provider-github_*
    for registry in std::fs::read_dir(&cache).ok()?.flatten() {
        let gh = registry.path().join("integrations/github");
        let Ok(versions) = std::fs::read_dir(&gh) else { continue };
        for ver in versions.flatten() {
            let Ok(arches) = std::fs::read_dir(ver.path()) else { continue };
            for arch in arches.flatten() {
                let Ok(files) = std::fs::read_dir(arch.path()) else { continue };
                for f in files.flatten() {
                    let name = f.file_name();
                    if name.to_string_lossy().starts_with("terraform-provider-github") {
                        return Some(f.path());
                    }
                }
            }
        }
    }
    None
}

fn skip_if_missing() -> Option<PathBuf> {
    let binary = locate_null_provider();
    if binary.is_none() {
        eprintln!(
            "skip: terraform-provider-null binary not found. \
             Download via:\n  \
             curl -fsSL https://releases.hashicorp.com/\
             terraform-provider-null/3.2.4/\
             terraform-provider-null_3.2.4_darwin_arm64.zip -o /tmp/null.zip && \
             unzip /tmp/null.zip -d magma-test/fixtures/providers/",
        );
    }
    binary
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_null_provider_handshake() {
    let Some(binary) = skip_if_missing() else {
        return;
    };

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(2),
        ..PluginSpec::default()
    };

    let plugin = Plugin::spawn(spec).await.expect("spawn real null provider");
    let hs = plugin.handshake();

    // null v3.2.4 actually speaks tfplugin5 over a Unix domain socket.
    // The test accepts both v5/v6 and tcp/unix so it works against
    // current null + future providers that may bump protocol or
    // network transport.
    assert_eq!(hs.core_protocol, 1, "core protocol must be 1");
    assert!(
        matches!(
            hs.app_protocol,
            magma_protocol::PluginProtocol::V5 | magma_protocol::PluginProtocol::V6,
        ),
        "expected v5 or v6, got {:?}",
        hs.app_protocol,
    );
    assert!(
        hs.network == "tcp" || hs.network == "unix",
        "expected tcp or unix network, got {:?}",
        hs.network,
    );
    assert_eq!(hs.proto_type, "grpc");
    assert!(
        hs.cert_pem_base64.is_some(),
        "real provider always emits cert"
    );
    eprintln!(
        "null provider handshake: protocol={:?} network={} address={}",
        hs.app_protocol, hs.network, hs.address,
    );

    drop(plugin);
}

// End-to-end against the REAL null provider: spawn → go-plugin
// handshake → mTLS → ALPN-h2 → gRPC GetSchema. PASSES.
//
// History: this was long #[ignore]d under the belief that rustls↔Go-tls
// interop was broken. It was NOT — the TLS handshake always succeeded.
// Two unrelated bugs in magma-plugin produced an opaque "transport
// error" that masqueraded as a TLS failure (2026-06-03):
//   1. dial() used an `https://` tonic Endpoint while the custom
//      connector already does TLS → tonic refused with "Connecting to
//      HTTPS without TLS enabled". Fixed to `http://`.
//   2. PLUGIN_CLIENT_CERT was sent base64(PEM); go-plugin feeds it
//      straight to AppendCertsFromPEM → "client cert provided but failed
//      to parse" → post-handshake broken pipe. Fixed to raw PEM.
// null v3.2.4 is an SDKv2 provider → it speaks tfplugin5, so this uses
// the v5 client + GetSchema (a v6 provider would use tfplugin6). Still
// requires the vendored binary, hence skip_if_missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_null_provider_schema() {
    let Some(binary) = skip_if_missing() else {
        return;
    };

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(2),
        ..PluginSpec::default()
    };

    let mut plugin = Plugin::spawn(spec).await.expect("spawn");
    let channel = plugin.dial().await.expect("dial gRPC").clone();
    // null v3.2.4 speaks tfplugin5 (SDKv2). Use the v5 client + GetSchema.
    let mut client = magma_protocol::tfplugin5::provider_client::ProviderClient::new(channel);

    let resp = client
        .get_schema(magma_protocol::tfplugin5::get_provider_schema::Request {})
        .await
        .expect("GetSchema against real null provider")
        .into_inner();

    eprintln!(
        "null provider schema: resources={:?} data_sources={:?} diagnostics={}",
        resp.resource_schemas.keys().collect::<Vec<_>>(),
        resp.data_source_schemas.keys().collect::<Vec<_>>(),
        resp.diagnostics.len(),
    );

    // The null provider exposes:
    //   - null_resource (managed)
    //   - null_data_source (data)
    assert!(
        resp.resource_schemas.contains_key("null_resource"),
        "null_resource resource schema present, got: {:?}",
        resp.resource_schemas.keys().collect::<Vec<_>>(),
    );
    assert!(
        resp.data_source_schemas.contains_key("null_data_source"),
        "null_data_source data-source schema present, got: {:?}",
        resp.data_source_schemas.keys().collect::<Vec<_>>(),
    );
    assert!(
        resp.diagnostics.is_empty(),
        "no diagnostics expected from schema read",
    );

    // The null_resource schema has a `triggers` attribute (map<string, string>).
    let null_resource = resp.resource_schemas.get("null_resource").unwrap();
    let block = null_resource
        .block
        .as_ref()
        .expect("null_resource has a block");
    let attr_names: Vec<&str> = block.attributes.iter().map(|a| a.name.as_str()).collect();
    assert!(
        attr_names.contains(&"triggers") || attr_names.contains(&"id"),
        "null_resource block has triggers or id attribute, got: {attr_names:?}",
    );
}

// Full Create lifecycle against the REAL null provider via tfplugin5
// (SDKv2): Configure → PlanResourceChange → ApplyResourceChange. Proves
// magma can drive a real provider RPC to MATERIALIZE a resource, using
// JSON-encoded DynamicValues (tfplugin accepts msgpack OR json; a typed
// msgpack codec is a later optimization, not a correctness requirement
// for talking to a provider). This is the end-to-end shape the magma
// apply engine wires through (the same flow with credentialed config
// drives github_repository creation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_null_provider_lifecycle() {
    use magma_protocol::tfplugin5;
    let Some(binary) = skip_if_missing() else {
        return;
    };

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(2),
        ..PluginSpec::default()
    };

    let mut plugin = Plugin::spawn(spec).await.expect("spawn");
    let channel = plugin.dial().await.expect("dial").clone();
    let mut client = tfplugin5::provider_client::ProviderClient::new(channel);

    // 1. Configure with an empty config (null takes no provider config).
    let configure_resp = client
        .configure(tfplugin5::configure::Request {
            terraform_version: "1.7.0".into(),
            config: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: b"{}".to_vec(),
            }),
            client_capabilities: None,
        })
        .await
        .expect("Configure RPC")
        .into_inner();
    eprintln!("configure diagnostics: {:?}", configure_resp.diagnostics);

    // 2. PlanResourceChange for a fresh null_resource (Create).
    let proposed = serde_json::json!({
        "triggers": { "magma_test_trigger": "v1" },
        "id": null,
    });
    let plan_resp = client
        .plan_resource_change(tfplugin5::plan_resource_change::Request {
            type_name: "null_resource".into(),
            prior_state: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: b"null".to_vec(),
            }),
            proposed_new_state: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: serde_json::to_vec(&proposed).unwrap(),
            }),
            config: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: serde_json::to_vec(&proposed).unwrap(),
            }),
            prior_private: vec![],
            provider_meta: None,
            client_capabilities: None,
            prior_identity: None,
        })
        .await
        .expect("PlanResourceChange RPC")
        .into_inner();
    eprintln!("plan diagnostics: {:?}", plan_resp.diagnostics);
    assert!(
        plan_resp.diagnostics.is_empty(),
        "plan failed: {:?}",
        plan_resp.diagnostics,
    );

    // 3. ApplyResourceChange — use the planned_state from the plan response.
    let apply_resp = client
        .apply_resource_change(tfplugin5::apply_resource_change::Request {
            type_name: "null_resource".into(),
            prior_state: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: b"null".to_vec(),
            }),
            planned_state: plan_resp.planned_state,
            config: Some(tfplugin5::DynamicValue {
                msgpack: vec![],
                json: serde_json::to_vec(&proposed).unwrap(),
            }),
            planned_private: plan_resp.planned_private,
            provider_meta: None,
            planned_identity: None,
        })
        .await
        .expect("ApplyResourceChange RPC")
        .into_inner();
    eprintln!("apply diagnostics: {:?}", apply_resp.diagnostics);
    assert!(
        apply_resp.diagnostics.is_empty(),
        "apply failed: {:?}",
        apply_resp.diagnostics,
    );
    let new_state = apply_resp.new_state.expect("apply produced no new_state");
    // A real create ran through the provider (all three RPCs returned
    // zero diagnostics) and produced a non-empty new_state. Providers
    // respond with a MSGPACK-encoded DynamicValue (the `msgpack` field,
    // not `json`) — decoding it back to attributes (to read the computed
    // `id`) is the msgpack-codec task; SENDING json config already works.
    eprintln!(
        "apply new_state: msgpack_len={} json_len={}",
        new_state.msgpack.len(),
        new_state.json.len()
    );
    assert!(
        !new_state.msgpack.is_empty() || !new_state.json.is_empty(),
        "provider returned an empty new_state — create did not materialize",
    );

    // 4. Stop the provider cleanly.
    let _ = client.stop(tfplugin5::stop::Request {}).await;

    drop(plugin);
}

// Proves the provider-RPC path against the REAL github provider — the
// actual rio target (executor:magma reconciles github_repository).
// FINDING: terraform-provider-github v6.12.1 negotiates protocol **v5**
// (the "6" is the provider version; it's an SDKv2 provider → tfplugin5,
// NOT framework/v6). So the registry must dispatch the gRPC client by
// the negotiated handshake.app_protocol, never by the provider version.
// GetSchema needs no credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_github_provider_schema() {
    use magma_protocol::tfplugin5;
    let Some(binary) = locate_cached_github_provider() else {
        eprintln!(
            "skip: github provider not in ~/.terraform.d/plugin-cache. \
             Populate via `tofu init` in a workspace using integrations/github."
        );
        return;
    };
    eprintln!("github provider binary: {}", binary.display());

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(2),
        ..PluginSpec::default()
    };

    let mut plugin = Plugin::spawn(spec).await.expect("spawn github provider");
    let proto = plugin.handshake().app_protocol;
    eprintln!("github handshake protocol: {proto:?}");
    assert_eq!(
        proto,
        magma_protocol::PluginProtocol::V5,
        "github v6.12.1 is an SDKv2 provider — expected protocol v5",
    );
    let channel = plugin.dial().await.expect("dial github gRPC").clone();
    let mut client = tfplugin5::provider_client::ProviderClient::new(channel);

    let resp = client
        .get_schema(tfplugin5::get_provider_schema::Request {})
        .await
        .expect("GetSchema against real github provider")
        .into_inner();

    let resources: Vec<&str> = resp.resource_schemas.keys().map(|k| k.as_str()).collect();
    eprintln!(
        "github provider: {} resources, {} data sources, {} diagnostics",
        resp.resource_schemas.len(),
        resp.data_source_schemas.len(),
        resp.diagnostics.len(),
    );
    assert!(
        resp.resource_schemas.contains_key("github_repository"),
        "github_repository schema present (got {} resources incl: {:?})",
        resources.len(),
        &resources.iter().take(8).collect::<Vec<_>>(),
    );

    let _ = client.stop(tfplugin5::stop::Request {}).await;
    drop(plugin);
}
