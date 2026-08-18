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

/// Is this binary executable by the HOST, not merely present on disk?
///
/// The vendored fixture is `terraform-provider-null_3.2.4_darwin_arm64` — a
/// Mach-O — and it is COMMITTED to the repo. So on a Linux runner it is very
/// much present, `path.exists()` is true, the skip never fires, and the test
/// dies at `Plugin::spawn(...).expect(...)` with an exec-format error. That
/// failure kept magma's whole Test gate red, which kept the release from ever
/// shipping magma-types / magma-config, which is what magma-lava, lava,
/// lava-operator and pangea-operator are all waiting on.
///
/// The module doc above states the intended behaviour plainly — "tests
/// skip-with-print when the binary is absent (Linux CI without the download
/// step...)". That premise held until the binary was committed; presence
/// stopped implying runnability and the guard silently became a no-op.
///
/// Magic bytes rather than a trial exec: it costs 4 bytes and cannot leave a
/// stray process behind if the spawn half-succeeds.
fn is_host_executable(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    // ELF: 0x7F "ELF". Mach-O 64-bit: 0xFEEDFACF, byte-swapped 0xCFFAEDFE.
    let is_elf = magic == [0x7F, b'E', b'L', b'F'];
    let is_macho = magic == [0xFE, 0xED, 0xFA, 0xCF] || magic == [0xCF, 0xFA, 0xED, 0xFE];
    if cfg!(target_os = "macos") {
        is_macho
    } else if cfg!(target_os = "linux") {
        is_elf
    } else {
        // Unknown host: let the spawn decide rather than skip silently.
        true
    }
}

/// Locate the vendored null-provider binary. Returns `None` if absent
/// (tests skip-with-print rather than fail in that case).
fn locate_null_provider() -> Option<PathBuf> {
    let candidates = [
        "magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
        "../magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() && is_host_executable(&path) {
            return Some(path.canonicalize().unwrap_or(path));
        }
    }
    // Look relative to CARGO_MANIFEST_DIR for the magma-test crate.
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest_dir)
            .join("fixtures/providers/terraform-provider-null_v3.2.4_x5");
        if p.exists() && is_host_executable(&p) {
            return Some(p);
        }
    }
    None
}

fn skip_if_missing() -> Option<PathBuf> {
    let binary = locate_null_provider();
    if binary.is_none() {
        eprintln!(
            "skip: no terraform-provider-null binary this host can RUN \
             (absent, or present but built for another platform — the \
             vendored fixture is darwin_arm64, so a Linux runner skips here). \
             Download the matching build via:\n  \
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

// ── CORRECTED 2026-08-18: this was NOT a TLS problem. ────────────────
//
// This test was `#[ignore]`d with the note "rustls↔Go-tls interop debug needed
// … the TLS handshake currently fails with a generic transport error". That
// diagnosis was wrong, and it kept a working capability shelved.
//
// The measured failure was:
//
//   Status { code: Unimplemented, message: "unknown service tfplugin6.Provider" }
//
// A gRPC *status* is a reply. Receiving one proves the mTLS handshake
// SUCCEEDED — rcgen + rustls 0.23 + the custom peer verifier all work against a
// real Go provider. What failed is one line above: the test built a
// `tfplugin6::ProviderClient` and pointed it at null v3.2.4, which speaks
// tfplugin5 — as this file's own comment says twelve lines earlier.
//
// The fix is to stop bypassing magma's own abstraction. `ProviderConn::new`
// takes the negotiated `PluginProtocol` precisely so a caller does not have to
// know which wire the provider speaks, and `get_schema()` dispatches to v5's
// `GetSchema` or v6's `GetProviderSchema` accordingly. Verified green against
// hashicorp/null v3.2.4 (v5, 1 resource + 1 data source) and against
// Lucky3028/discord v2.7.0 (v5, 19 resources + 7 data sources).
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
    let protocol = plugin.handshake().app_protocol;
    let channel = plugin.dial().await.expect("dial gRPC").clone();

    // Through ProviderConn, not a hardcoded protocol client.
    let mut conn = magma_plugin::provider::ProviderConn::new(channel.clone(), protocol);
    let schema = conn
        .get_schema()
        .await
        .expect("get_schema against real null provider");
    assert!(
        schema.resources.contains_key("null_resource"),
        "null_resource present via ProviderConn, got: {:?}",
        schema.resources.keys().collect::<Vec<_>>(),
    );
    assert!(
        schema.data_sources.contains_key("null_data_source"),
        "null_data_source present via ProviderConn, got: {:?}",
        schema.data_sources.keys().collect::<Vec<_>>(),
    );

    // The raw v5 surface still answers too — this is what a schema DUMP needs,
    // because ProviderConn returns implied cty types and drops the
    // required/optional/computed flags and descriptions a generator wants.
    let mut v5 = magma_protocol::tfplugin5::provider_client::ProviderClient::new(channel);
    let resp = v5
        .get_schema(magma_protocol::tfplugin5::get_provider_schema::Request {})
        .await
        .expect("v5 GetSchema against real null provider")
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

// Still ignored, but NOT for the reason previously recorded here. The old note
// blamed "rustls↔Go-tls interop"; the sibling schema test above now runs green
// un-ignored, which proves mTLS to a real Go provider works. The actual blocker
// is the same one that shelved that test: this body drives `tfplugin6`'s client
// and v6 request types (`configure_provider`, `ClientCapabilities`) against null
// v3.2.4, which speaks tfplugin5. Every RPC below therefore answers
// `Unimplemented: unknown service tfplugin6.Provider`.
//
// Unlike the schema test, this one cannot be fixed by swapping in
// `ProviderConn`: it exercises the full configure→plan→apply lifecycle, and the
// v5 request/response types differ field-by-field from the v6 ones written
// here, so it needs a rewrite rather than a redirect. Left ignored with an
// accurate reason instead of a wrong one — a stale diagnosis costs the next
// reader more than an open TODO does.
#[ignore = "written against tfplugin6 types; null v3.2.4 speaks tfplugin5 — needs a v5 rewrite, NOT a TLS fix"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_null_provider_lifecycle() {
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
    let mut client = ProviderClient::new(channel);

    // 1. ConfigureProvider with an empty config (null takes no provider config).
    let configure_req = tfplugin6::configure_provider::Request {
        terraform_version: "1.7.0".into(),
        config: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: b"{}".to_vec(),
        }),
        client_capabilities: None,
    };
    let configure_resp = client
        .configure_provider(configure_req)
        .await
        .expect("ConfigureProvider RPC")
        .into_inner();
    eprintln!("configure diagnostics: {:?}", configure_resp.diagnostics);

    // 2. PlanResourceChange for a fresh null_resource (Create).
    //    Encode the proposed state as JSON: { "triggers": {"key": "value"}, "id": null }.
    let proposed = serde_json::json!({
        "triggers": { "magma_test_trigger": "v1" },
        "id": null,
    });
    let plan_req = tfplugin6::plan_resource_change::Request {
        type_name: "null_resource".into(),
        prior_state: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: b"null".to_vec(),
        }),
        proposed_new_state: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: serde_json::to_vec(&proposed).unwrap(),
        }),
        config: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: serde_json::to_vec(&proposed).unwrap(),
        }),
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
    eprintln!("plan diagnostics: {:?}", plan_resp.diagnostics);
    // Schema-valid plan should succeed (no diagnostics from the provider).
    assert!(
        plan_resp.diagnostics.is_empty(),
        "plan failed: {:?}",
        plan_resp.diagnostics,
    );

    // 3. ApplyResourceChange — use the planned_state from the plan response.
    let apply_req = tfplugin6::apply_resource_change::Request {
        type_name: "null_resource".into(),
        prior_state: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: b"null".to_vec(),
        }),
        planned_state: plan_resp.planned_state,
        config: Some(tfplugin6::DynamicValue {
            msgpack: vec![],
            json: serde_json::to_vec(&proposed).unwrap(),
        }),
        planned_private: plan_resp.planned_private,
        provider_meta: None,
        planned_identity: None,
    };
    let apply_resp = client
        .apply_resource_change(apply_req)
        .await
        .expect("ApplyResourceChange RPC")
        .into_inner();
    eprintln!("apply diagnostics: {:?}", apply_resp.diagnostics);
    assert!(
        apply_resp.diagnostics.is_empty(),
        "apply failed: {:?}",
        apply_resp.diagnostics,
    );
    assert!(
        apply_resp.new_state.is_some(),
        "apply produced no new_state",
    );

    // 4. Stop the provider cleanly.
    let _ = client
        .stop_provider(tfplugin6::stop_provider::Request {})
        .await;

    drop(plugin);
}
