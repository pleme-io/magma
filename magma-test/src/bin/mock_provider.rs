//! Mock Terraform / OpenTofu provider — implements a minimal subset of
//! the tfplugin6 gRPC service so magma-plugin's integration tests can
//! exercise the full protocol layer (handshake + dial + GetProviderSchema
//! + PlanResourceChange + ApplyResourceChange) without requiring a real
//! cloud provider binary.
//!
//! Behavior:
//! 1. Validate `TF_PLUGIN_MAGIC_COOKIE` env var.
//! 2. Validate `PLUGIN_CLIENT_CERT` env var (base64-decodable DER).
//! 3. Generate own self-signed cert via rcgen; base64-encode the DER.
//! 4. Bind a TCP listener in [PLUGIN_MIN_PORT, PLUGIN_MAX_PORT].
//! 5. Print handshake line to stdout (with real provider cert).
//! 6. Serve tfplugin6 Provider gRPC service over plain TCP/h2c.
//!    GetProviderSchema returns a minimal real schema.
//!    PlanResourceChange + ApplyResourceChange return canned responses
//!    suitable for lifecycle testing. All other RPCs return
//!    `Status::unimplemented` via a macro.
//! 7. Idle / accept connections until killed by parent.

use std::env;
use std::io::Write;
use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
// Identity + ServerTlsConfig stay imported for the M0.x re-enable of
// server-side mTLS once tonic+rustls cert-acceptance is debugged
// against go-plugin's strict client-CA validation.
#[allow(unused_imports)]
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use magma_protocol::tfplugin6;
use magma_protocol::tfplugin6::provider_server::{Provider, ProviderServer};

const EXPECTED_COOKIE_KEY: &str = "TF_PLUGIN_MAGIC_COOKIE";
// Real Terraform / OpenTofu published cookie.
const EXPECTED_COOKIE_VAL: &str =
    "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2";

/// The implied cty type of `mock_resource` — MUST mirror the attribute
/// set `get_provider_schema` declares below (`id`, `name`,
/// `imported_by`, all strings). Kept as one function both call sites
/// share so the schema-vs-encoding pair can't drift.
fn mock_resource_implied_type() -> magma_cty::CtyType {
    magma_cty::CtyType::object([
        ("id".to_string(), magma_cty::CtyType::String),
        ("name".to_string(), magma_cty::CtyType::String),
        ("imported_by".to_string(), magma_cty::CtyType::String),
    ])
}

/// The implied cty type of `mock_replace_resource` — a second resource
/// type carrying one attribute (`immutable_field`) `plan_resource_change`
/// treats as ForceNew, exercising the requires-replace destroy+create
/// path end-to-end (see `magma-apply::engine::apply_one`'s `is_replace`
/// branch + `magma-apply/tests/integration_replace_destroy_then_create.rs`).
/// Kept SEPARATE from `mock_resource` so this test fixture can never
/// perturb the existing `mock_resource`-shaped lifecycle/import tests.
fn mock_replace_resource_implied_type() -> magma_cty::CtyType {
    magma_cty::CtyType::object([
        ("id".to_string(), magma_cty::CtyType::String),
        ("name".to_string(), magma_cty::CtyType::String),
        ("immutable_field".to_string(), magma_cty::CtyType::String),
    ])
}

/// Decode a wire `DynamicValue`'s `immutable_field` string attribute
/// against `mock_replace_resource_implied_type()`. `None` for an absent/
/// null value (a create's `prior_state`, or a destroy's `planned_state`)
/// or a decode failure.
fn immutable_field_of(dv: &Option<tfplugin6::DynamicValue>) -> Option<String> {
    let dv = dv.as_ref()?;
    let json = magma_cty::DynamicValue {
        msgpack: dv.msgpack.clone(),
    }
    .to_json(&mock_replace_resource_implied_type())
    .ok()?;
    json.get("immutable_field")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

#[derive(Default)]
struct MockProvider;

#[tonic::async_trait]
impl Provider for MockProvider {
    async fn get_metadata(
        &self,
        _req: Request<tfplugin6::get_metadata::Request>,
    ) -> Result<Response<tfplugin6::get_metadata::Response>, Status> {
        Ok(Response::new(tfplugin6::get_metadata::Response {
            server_capabilities: None,
            diagnostics: vec![],
            data_sources: vec![],
            resources: vec![],
            functions: vec![],
            ephemeral_resources: vec![],
            list_resources: vec![],
            state_stores: vec![],
            actions: vec![],
        }))
    }

    async fn get_provider_schema(
        &self,
        _req: Request<tfplugin6::get_provider_schema::Request>,
    ) -> Result<Response<tfplugin6::get_provider_schema::Response>, Status> {
        // Minimal real schema: one resource type "mock_resource" with
        // three string attributes (id / name / imported_by) — enough
        // to prove the wire format works end-to-end, INCLUDING the
        // schema-driven cty msgpack round-trip `ConfiguredImportEnvironment`
        // (magma-apply::import_prepass) drives via
        // `ProviderConn::import_resource_state` + `DynamicValue.to_json`.
        // An empty-attribute block (the prior shape) only proved the
        // connection + RPC dispatch, never the actual attribute codec —
        // see `mock_resource_implied_type()` below, which the
        // `import_resource_state` handler encodes its canned state
        // against.
        fn string_attr(name: &str) -> tfplugin6::schema::Attribute {
            tfplugin6::schema::Attribute {
                name: name.to_string(),
                r#type: serde_json::to_vec(&serde_json::json!("string"))
                    .unwrap_or_default(),
                nested_type: None,
                description: String::new(),
                required: false,
                optional: true,
                computed: true,
                sensitive: false,
                description_kind: tfplugin6::StringKind::Plain as i32,
                deprecated: false,
                deprecation_message: String::new(),
                write_only: false,
            }
        }
        let block = tfplugin6::schema::Block {
            version: 0,
            attributes: vec![
                string_attr("id"),
                string_attr("name"),
                string_attr("imported_by"),
            ],
            block_types: vec![],
            description: "mock provider resource".into(),
            description_kind: tfplugin6::StringKind::Plain as i32,
            deprecated: false,
            deprecation_message: String::new(),
        };
        // Schema.version = 1: "mock_resource" has evolved once past its
        // original (version 0) shape, in which this same attribute was
        // named `legacy_owner` instead of `imported_by` — see
        // `upgrade_resource_state` below, which migrates that rename. A
        // provider bumping its schema version between releases (a routine
        // occurrence for actively maintained providers) is exactly the
        // scenario magma's UpgradeResourceState client wiring exists for.
        let schema = tfplugin6::Schema {
            version: 1,
            block: Some(block.clone()),
        };
        let replace_block = tfplugin6::schema::Block {
            version: 0,
            attributes: vec![
                string_attr("id"),
                string_attr("name"),
                string_attr("immutable_field"),
            ],
            block_types: vec![],
            description: "mock provider resource with a ForceNew attribute".into(),
            description_kind: tfplugin6::StringKind::Plain as i32,
            deprecated: false,
            deprecation_message: String::new(),
        };
        let replace_schema = tfplugin6::Schema {
            version: 0,
            block: Some(replace_block),
        };
        let mut resource_schemas = std::collections::HashMap::new();
        resource_schemas.insert("mock_resource".to_string(), schema.clone());
        resource_schemas.insert("mock_replace_resource".to_string(), replace_schema);

        Ok(Response::new(tfplugin6::get_provider_schema::Response {
            provider: Some(tfplugin6::Schema {
                version: 0,
                block: Some(tfplugin6::schema::Block {
                    version: 0,
                    attributes: vec![],
                    block_types: vec![],
                    description: "mock provider".into(),
                    description_kind: tfplugin6::StringKind::Plain as i32,
                    deprecated: false,
                    deprecation_message: String::new(),
                }),
            }),
            resource_schemas,
            data_source_schemas: Default::default(),
            functions: Default::default(),
            ephemeral_resource_schemas: Default::default(),
            list_resource_schemas: Default::default(),
            state_store_schemas: Default::default(),
            action_schemas: Default::default(),
            diagnostics: vec![],
            provider_meta: None,
            server_capabilities: None,
        }))
    }

    async fn validate_provider_config(
        &self,
        _req: Request<tfplugin6::validate_provider_config::Request>,
    ) -> Result<Response<tfplugin6::validate_provider_config::Response>, Status> {
        Ok(Response::new(
            tfplugin6::validate_provider_config::Response {
                diagnostics: vec![],
            },
        ))
    }

    async fn validate_resource_config(
        &self,
        _req: Request<tfplugin6::validate_resource_config::Request>,
    ) -> Result<Response<tfplugin6::validate_resource_config::Response>, Status> {
        Ok(Response::new(
            tfplugin6::validate_resource_config::Response {
                diagnostics: vec![],
            },
        ))
    }

    async fn configure_provider(
        &self,
        _req: Request<tfplugin6::configure_provider::Request>,
    ) -> Result<Response<tfplugin6::configure_provider::Response>, Status> {
        Ok(Response::new(tfplugin6::configure_provider::Response {
            diagnostics: vec![],
        }))
    }

    async fn plan_resource_change(
        &self,
        req: Request<tfplugin6::plan_resource_change::Request>,
    ) -> Result<Response<tfplugin6::plan_resource_change::Response>, Status> {
        let r = req.into_inner();
        // `mock_replace_resource` treats `immutable_field` as ForceNew:
        // when there IS a prior instance (this isn't a create) and its
        // `immutable_field` differs from the proposed value, report it in
        // `requires_replace` — exactly what a real SDKv2/framework
        // provider does for a ForceNew attribute. Exercises
        // `ProviderConn::plan_resource_change`'s `requires_replace`
        // decode + `magma-apply::engine::apply_one`'s `is_replace`
        // branch over the REAL wire protocol (see
        // `magma-apply/tests/integration_replace_destroy_then_create.rs`).
        let requires_replace = if r.type_name == "mock_replace_resource" {
            match (
                immutable_field_of(&r.prior_state),
                immutable_field_of(&r.proposed_new_state),
            ) {
                (Some(prior), Some(proposed)) if prior != proposed => {
                    vec![tfplugin6::AttributePath {
                        steps: vec![tfplugin6::attribute_path::Step {
                            selector: Some(
                                tfplugin6::attribute_path::step::Selector::AttributeName(
                                    "immutable_field".to_string(),
                                ),
                            ),
                        }],
                    }]
                }
                _ => vec![],
            }
        } else {
            vec![]
        };
        // Canned response: planned_state = proposed_new_state (no changes).
        Ok(Response::new(tfplugin6::plan_resource_change::Response {
            planned_state: r.proposed_new_state,
            requires_replace,
            planned_private: vec![],
            diagnostics: vec![],
            legacy_type_system: false,
            planned_identity: None,
            deferred: None,
        }))
    }

    async fn apply_resource_change(
        &self,
        req: Request<tfplugin6::apply_resource_change::Request>,
    ) -> Result<Response<tfplugin6::apply_resource_change::Response>, Status> {
        let r = req.into_inner();
        // The synthetic failure a REAL provider gives when it receives a
        // malformed single-call "replace" — `prior_state` from the OLD
        // instance paired with a `planned_state` whose ForceNew
        // `immutable_field` already differs. This is exactly what the
        // pre-fix `apply_one` catch-all used to send for every action
        // alike; a properly orchestrated destroy (`planned_state` null)
        // or create (`prior_state` null) never hits this arm, since one
        // side is always null in that sequence.
        if r.type_name == "mock_replace_resource" {
            if let (Some(prior), Some(planned)) = (
                immutable_field_of(&r.prior_state),
                immutable_field_of(&r.planned_state),
            ) {
                if prior != planned {
                    return Ok(Response::new(tfplugin6::apply_resource_change::Response {
                        new_state: None,
                        private: vec![],
                        diagnostics: vec![tfplugin6::Diagnostic {
                            severity: tfplugin6::diagnostic::Severity::Error as i32,
                            summary: "cannot update immutable_field in place".into(),
                            detail: format!(
                                "mock: immutable_field is ForceNew (prior={prior:?} \
                                 planned={planned:?}) — a real provider hard-fails or \
                                 silently ignores this single-call request"
                            ),
                            attribute: None,
                        }],
                        legacy_type_system: false,
                        new_identity: None,
                    }));
                }
            }
        }
        // Canned response: new_state = planned_state (apply succeeds as-is).
        Ok(Response::new(tfplugin6::apply_resource_change::Response {
            new_state: r.planned_state,
            private: vec![],
            diagnostics: vec![],
            legacy_type_system: false,
            new_identity: None,
        }))
    }

    // ── Stubs (return unimplemented; not exercised by the M0 lifecycle test) ──

    async fn read_resource(
        &self,
        req: Request<tfplugin6::read_resource::Request>,
    ) -> Result<Response<tfplugin6::read_resource::Response>, Status> {
        // Exercises magma-apply's plan-time refresh (`refresh_state` /
        // `refresh_named`) over the real wire path — see
        // `magma-test/tests/integration_refresh_then_plan.rs` +
        // `integration_upgrade_resource_state.rs`. Canned drift, mirroring
        // `import_resource_state`'s "missing"-id sentinel convention
        // above: decode the requested `current_state`'s `id` attribute; an
        // id of `"gone"` means the resource was deleted out-of-band (the
        // mock returns a null `new_state`, exactly the signal a real
        // provider sends for a resource manually removed outside the
        // tool), any other id is echoed back unchanged (no drift) — which
        // is also exactly the "nothing changed since the last apply" case
        // `refresh_state`'s UpgradeResourceState-migration tests exercise.
        let r = req.into_inner();
        let is_gone = r
            .current_state
            .as_ref()
            .and_then(|dv| {
                magma_cty::DynamicValue {
                    msgpack: dv.msgpack.clone(),
                }
                .to_json(&mock_resource_implied_type())
                .ok()
            })
            .and_then(|json| json.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .is_some_and(|id| id == "gone");

        Ok(Response::new(tfplugin6::read_resource::Response {
            new_state: if is_gone { None } else { r.current_state },
            diagnostics: vec![],
            private: vec![],
            deferred: None,
            new_identity: None,
        }))
    }

    async fn import_resource_state(
        &self,
        req: Request<tfplugin6::import_resource_state::Request>,
    ) -> Result<Response<tfplugin6::import_resource_state::Response>, Status> {
        // Exercise the real client → prepass → absorb flow. The mock
        // adopts ANY (type_name, id) by returning a canned state whose
        // attributes echo the requested id — exactly what a real
        // provider's ImportResourceState does for a resource that
        // exists. A sentinel id of "missing" yields an ERROR
        // diagnostic so the per-resource-failure-isolation law can be
        // exercised against the real wire path.
        let r = req.into_inner();
        if r.id == "missing" {
            return Ok(Response::new(tfplugin6::import_resource_state::Response {
                imported_resources: vec![],
                diagnostics: vec![tfplugin6::Diagnostic {
                    severity: tfplugin6::diagnostic::Severity::Error as i32,
                    summary: "resource not found".into(),
                    detail: format!("mock: no resource with id {:?}", r.id),
                    attribute: None,
                }],
                deferred: None,
            }));
        }
        let state_json = serde_json::json!({
            "id":   r.id,
            "name": r.id,
            "imported_by": "mock_provider",
        });
        // Encode BOTH wire fields:
        //   * `.msgpack`, type-driven against `mock_resource_implied_type()`
        //     (the SAME shape `get_provider_schema` declares above) — the
        //     field every REAL provider actually populates, and the one
        //     `ConfiguredImportEnvironment` (magma-apply::import_prepass)
        //     decodes via `DynamicValue::to_json(&implied)`.
        //   * `.json`, a raw debug-only echo — kept so the pre-existing
        //     `PluginImportEnvironment` (raw/unconfigured-channel) law
        //     battery in this crate's `tests/integration_import_resource_state.rs`
        //     keeps exercising its own (JSON-only) decode path unchanged.
        // A real provider populates only `.msgpack`; the mock populates
        // both so ONE handler proves both magma-side decoders.
        let msgpack = magma_cty::DynamicValue::from_json(&state_json, &mock_resource_implied_type())
            .map(|dv| dv.msgpack)
            .unwrap_or_default();
        Ok(Response::new(tfplugin6::import_resource_state::Response {
            imported_resources: vec![tfplugin6::import_resource_state::ImportedResource {
                type_name: r.type_name,
                state: Some(tfplugin6::DynamicValue {
                    msgpack,
                    json: serde_json::to_vec(&state_json).unwrap_or_default(),
                }),
                private: vec![],
                identity: None,
            }],
            diagnostics: vec![],
            deferred: None,
        }))
    }

    async fn move_resource_state(
        &self,
        _req: Request<tfplugin6::move_resource_state::Request>,
    ) -> Result<Response<tfplugin6::move_resource_state::Response>, Status> {
        Err(Status::unimplemented("mock: move_resource_state"))
    }

    async fn read_data_source(
        &self,
        _req: Request<tfplugin6::read_data_source::Request>,
    ) -> Result<Response<tfplugin6::read_data_source::Response>, Status> {
        Err(Status::unimplemented("mock: read_data_source"))
    }

    async fn validate_data_resource_config(
        &self,
        _req: Request<tfplugin6::validate_data_resource_config::Request>,
    ) -> Result<Response<tfplugin6::validate_data_resource_config::Response>, Status> {
        Err(Status::unimplemented("mock: validate_data_resource_config"))
    }

    async fn upgrade_resource_state(
        &self,
        req: Request<tfplugin6::upgrade_resource_state::Request>,
    ) -> Result<Response<tfplugin6::upgrade_resource_state::Response>, Status> {
        // Exercise the real client → magma-apply refresh flow. `version`
        // is the caller's STORED schema_version (per the protocol, "core
        // does not have access to the schema of prior_version" — the raw
        // state is whatever shape that older schema used). For
        // "mock_resource" version 0, that shape used `legacy_owner`
        // instead of the current (version 1) `imported_by` — a realistic
        // field-rename schema migration. `raw_state.json` carries the
        // JSON-encoded prior attributes (magma never sends the legacy
        // flatmap format).
        let r = req.into_inner();
        let raw = r.raw_state.map(|rs| rs.json).unwrap_or_default();
        let mut v: serde_json::Value =
            serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Object(Default::default()));
        if r.version < 1 {
            if let Some(obj) = v.as_object_mut() {
                if let Some(legacy) = obj.remove("legacy_owner") {
                    obj.insert("imported_by".to_string(), legacy);
                }
            }
        }
        let msgpack = magma_cty::DynamicValue::from_json(&v, &mock_resource_implied_type())
            .map(|dv| dv.msgpack)
            .unwrap_or_default();
        Ok(Response::new(tfplugin6::upgrade_resource_state::Response {
            upgraded_state: Some(tfplugin6::DynamicValue {
                msgpack,
                json: Vec::new(),
            }),
            diagnostics: vec![],
        }))
    }

    async fn get_resource_identity_schemas(
        &self,
        _req: Request<tfplugin6::get_resource_identity_schemas::Request>,
    ) -> Result<Response<tfplugin6::get_resource_identity_schemas::Response>, Status> {
        Err(Status::unimplemented("mock: get_resource_identity_schemas"))
    }

    async fn upgrade_resource_identity(
        &self,
        _req: Request<tfplugin6::upgrade_resource_identity::Request>,
    ) -> Result<Response<tfplugin6::upgrade_resource_identity::Response>, Status> {
        Err(Status::unimplemented("mock: upgrade_resource_identity"))
    }

    async fn get_functions(
        &self,
        _req: Request<tfplugin6::get_functions::Request>,
    ) -> Result<Response<tfplugin6::get_functions::Response>, Status> {
        Ok(Response::new(tfplugin6::get_functions::Response {
            functions: Default::default(),
            diagnostics: vec![],
        }))
    }

    async fn call_function(
        &self,
        _req: Request<tfplugin6::call_function::Request>,
    ) -> Result<Response<tfplugin6::call_function::Response>, Status> {
        Err(Status::unimplemented("mock: call_function"))
    }

    async fn stop_provider(
        &self,
        _req: Request<tfplugin6::stop_provider::Request>,
    ) -> Result<Response<tfplugin6::stop_provider::Response>, Status> {
        Ok(Response::new(tfplugin6::stop_provider::Response {
            error: String::new(),
        }))
    }

    async fn validate_ephemeral_resource_config(
        &self,
        _req: Request<tfplugin6::validate_ephemeral_resource_config::Request>,
    ) -> Result<Response<tfplugin6::validate_ephemeral_resource_config::Response>, Status> {
        Err(Status::unimplemented(
            "mock: validate_ephemeral_resource_config",
        ))
    }

    async fn open_ephemeral_resource(
        &self,
        _req: Request<tfplugin6::open_ephemeral_resource::Request>,
    ) -> Result<Response<tfplugin6::open_ephemeral_resource::Response>, Status> {
        Err(Status::unimplemented("mock: open_ephemeral_resource"))
    }

    async fn renew_ephemeral_resource(
        &self,
        _req: Request<tfplugin6::renew_ephemeral_resource::Request>,
    ) -> Result<Response<tfplugin6::renew_ephemeral_resource::Response>, Status> {
        Err(Status::unimplemented("mock: renew_ephemeral_resource"))
    }

    async fn close_ephemeral_resource(
        &self,
        _req: Request<tfplugin6::close_ephemeral_resource::Request>,
    ) -> Result<Response<tfplugin6::close_ephemeral_resource::Response>, Status> {
        Err(Status::unimplemented("mock: close_ephemeral_resource"))
    }

    async fn generate_resource_config(
        &self,
        _req: Request<tfplugin6::generate_resource_config::Request>,
    ) -> Result<Response<tfplugin6::generate_resource_config::Response>, Status> {
        Err(Status::unimplemented("mock: generate_resource_config"))
    }

    type ListResourceStream =
        tokio_stream::wrappers::ReceiverStream<Result<tfplugin6::list_resource::Event, Status>>;
    async fn list_resource(
        &self,
        _req: Request<tfplugin6::list_resource::Request>,
    ) -> Result<Response<Self::ListResourceStream>, Status> {
        Err(Status::unimplemented("mock: list_resource"))
    }

    async fn validate_list_resource_config(
        &self,
        _req: Request<tfplugin6::validate_list_resource_config::Request>,
    ) -> Result<Response<tfplugin6::validate_list_resource_config::Response>, Status> {
        Err(Status::unimplemented("mock: validate_list_resource_config"))
    }

    async fn validate_state_store_config(
        &self,
        _req: Request<tfplugin6::validate_state_store::Request>,
    ) -> Result<Response<tfplugin6::validate_state_store::Response>, Status> {
        Err(Status::unimplemented("mock: validate_state_store_config"))
    }

    async fn configure_state_store(
        &self,
        _req: Request<tfplugin6::configure_state_store::Request>,
    ) -> Result<Response<tfplugin6::configure_state_store::Response>, Status> {
        Err(Status::unimplemented("mock: configure_state_store"))
    }

    type ReadStateBytesStream = tokio_stream::wrappers::ReceiverStream<
        Result<tfplugin6::read_state_bytes::Response, Status>,
    >;
    async fn read_state_bytes(
        &self,
        _req: Request<tfplugin6::read_state_bytes::Request>,
    ) -> Result<Response<Self::ReadStateBytesStream>, Status> {
        Err(Status::unimplemented("mock: read_state_bytes"))
    }

    async fn write_state_bytes(
        &self,
        _req: Request<tonic::Streaming<tfplugin6::write_state_bytes::RequestChunk>>,
    ) -> Result<Response<tfplugin6::write_state_bytes::Response>, Status> {
        Err(Status::unimplemented("mock: write_state_bytes"))
    }

    async fn lock_state(
        &self,
        _req: Request<tfplugin6::lock_state::Request>,
    ) -> Result<Response<tfplugin6::lock_state::Response>, Status> {
        Err(Status::unimplemented("mock: lock_state"))
    }

    async fn unlock_state(
        &self,
        _req: Request<tfplugin6::unlock_state::Request>,
    ) -> Result<Response<tfplugin6::unlock_state::Response>, Status> {
        Err(Status::unimplemented("mock: unlock_state"))
    }

    async fn get_states(
        &self,
        _req: Request<tfplugin6::get_states::Request>,
    ) -> Result<Response<tfplugin6::get_states::Response>, Status> {
        Err(Status::unimplemented("mock: get_states"))
    }

    async fn delete_state(
        &self,
        _req: Request<tfplugin6::delete_state::Request>,
    ) -> Result<Response<tfplugin6::delete_state::Response>, Status> {
        Err(Status::unimplemented("mock: delete_state"))
    }

    async fn plan_action(
        &self,
        _req: Request<tfplugin6::plan_action::Request>,
    ) -> Result<Response<tfplugin6::plan_action::Response>, Status> {
        Err(Status::unimplemented("mock: plan_action"))
    }

    type InvokeActionStream =
        tokio_stream::wrappers::ReceiverStream<Result<tfplugin6::invoke_action::Event, Status>>;
    async fn invoke_action(
        &self,
        _req: Request<tfplugin6::invoke_action::Request>,
    ) -> Result<Response<Self::InvokeActionStream>, Status> {
        Err(Status::unimplemented("mock: invoke_action"))
    }

    async fn validate_action_config(
        &self,
        _req: Request<tfplugin6::validate_action_config::Request>,
    ) -> Result<Response<tfplugin6::validate_action_config::Response>, Status> {
        Err(Status::unimplemented("mock: validate_action_config"))
    }
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider once for this process.
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    // 1. Validate magic cookie.
    let cookie = env::var(EXPECTED_COOKIE_KEY).unwrap_or_else(|_| {
        eprintln!("mock_provider: missing {EXPECTED_COOKIE_KEY}");
        std::process::exit(1);
    });
    if cookie != EXPECTED_COOKIE_VAL {
        eprintln!("mock_provider: magic cookie mismatch");
        std::process::exit(1);
    }

    // 2. Parent cert env var (AutoMTLS). OPTIONAL: `magma_plugin::Plugin::spawn`
    // only sets `PLUGIN_CLIENT_CERT` when `PluginSpec.secure == true`; with
    // `secure: false` (the mock's plaintext-h2c path) it is intentionally
    // absent. Decode it when present so the mTLS-serving path can consume it;
    // when absent, serve plain h2c (the mock never wires TLS regardless — see
    // the `let _ = …` discard below). A *malformed* cert is still fatal.
    let parent_pem_bytes = match env::var("PLUGIN_CLIENT_CERT") {
        Ok(b64) => B64.decode(&b64).unwrap_or_else(|e| {
            eprintln!("mock_provider: PLUGIN_CLIENT_CERT not valid base64: {e}");
            std::process::exit(1);
        }),
        Err(_) => Vec::new(),
    };

    // 3. Generate own cert via rcgen (CA:true so the cert can self-sign
    // for client validation purposes when peer trust uses webpki).
    let key_pair = KeyPair::generate().expect("mock_provider: rcgen keypair");
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("mock_provider: cert params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "mock-provider");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let cert = params
        .self_signed(&key_pair)
        .expect("mock_provider: self-sign");
    let provider_cert_pem = cert.pem();
    let provider_cert_der = cert.der().to_vec();
    let provider_key_pem = key_pair.serialize_pem();
    // Emit base64(PEM) per the go-plugin protocol expectation —
    // magma-plugin will decode the PEM and trust it as a peer cert.
    let provider_cert_b64 = B64.encode(provider_cert_pem.as_bytes());
    let _ = provider_cert_der; // kept for potential DER-output flows

    // 4. Bind a TCP listener in the requested port range.
    let min_port: u16 = env::var("PLUGIN_MIN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let max_port: u16 = env::var("PLUGIN_MAX_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25_000);

    let listener = bind_in_range(min_port, max_port).await.unwrap_or_else(|| {
        // Fall back to OS-assigned port if the range is unusable.
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| {
                l.set_nonblocking(true)?;
                TcpListener::from_std(l)
            })
            .expect("mock_provider: bind any port")
    });
    let local_addr: SocketAddr = listener.local_addr().expect("mock_provider: local_addr");

    // 5. Negotiate protocol version.
    let app_protocol = match env::var("PLUGIN_PROTOCOL_VERSIONS")
        .unwrap_or_else(|_| "5,6".into())
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .max()
    {
        Some(6) => 6,
        Some(5) => 5,
        _ => 6,
    };

    // 6. Emit handshake line.
    let handshake = format!("1|{app_protocol}|tcp|{local_addr}|grpc|{provider_cert_b64}",);
    {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{handshake}").expect("mock_provider: stdout write");
        out.flush().expect("mock_provider: stdout flush");
    }

    // 7. Serve tonic gRPC. mock_provider runs plain TCP/h2c — magma's
    // mTLS layer is exercised end-to-end by the real-null-provider
    // integration suite, not this mock suite. Plugins targeting this
    // mock set PluginSpec.secure = false.
    let _ = (&provider_cert_pem, &provider_key_pem, &parent_pem_bytes);
    let svc = ProviderServer::new(MockProvider);
    let stream = TcpListenerStream::new(listener);
    let _ = Server::builder()
        .add_service(svc)
        .serve_with_incoming(stream)
        .await;
}

async fn bind_in_range(min_port: u16, max_port: u16) -> Option<TcpListener> {
    for port in min_port..=max_port {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)).await {
            return Some(l);
        }
    }
    None
}
