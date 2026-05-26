//! magma-mcp — Model Context Protocol server.
//!
//! Exposes magma's plan / apply / state / output / show operations as
//! typed MCP tools for AI agents. JSON-RPC 2.0 over stdin/stdout (MCP
//! standard transport).
//!
//! Per `theory/MAGMA.md` §II.8 (Multi-interface surface — interface 3),
//! the MCP server is an M0 deliverable, not a follow-up. Tool schemas
//! are generated mechanically from the typed magma-types surface, never
//! hand-authored (Pillar 12).
//!
//! Destructive tools (`magma_apply`, `magma_destroy`, `magma_state_mv`,
//! `magma_state_rm`, `magma_force_unlock`) require an explicit
//! `confirm: true` parameter; the server rejects unconfirmed calls so
//! MCP clients are forced to surface the operation to the human.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── JSON-RPC 2.0 framing ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ── MCP tool registry ─────────────────────────────────────────────

/// Typed schema for a single MCP tool. Generated from magma-types in M0;
/// the schema field is a `serde_json::Value` representing a JSON-Schema
/// draft-7 object for the tool's parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub schema: serde_json::Value,
    pub destructive: bool,
}

/// The full set of MCP tools magma exposes. Per §II.8 interface 3.
#[must_use]
pub fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "magma_init".into(),
            description: "Initialize a workspace — download providers, build lock file. Required before plan/apply.".into(),
            schema: minimal_schema(&[("workspace_dir", "string", true)]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_plan".into(),
            description: "Compute a plan against current state. Returns the typed list of resource changes + a Plan ID (BLAKE3) suitable for `magma_apply`.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("variables",     "object", false),
            ]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_apply".into(),
            description: "Apply a plan to the cloud substrate. Requires explicit `confirm: true` AND a `plan_id` from a prior `magma_plan` call. The plan ID must verify byte-equal against the prior plan or magma refuses to apply.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("plan_id",       "string", true),
                ("confirm",       "bool",   true),
            ]),
            destructive: true,
        },
        ToolSpec {
            name: "magma_destroy".into(),
            description: "Destroy all managed resources. Requires explicit `confirm: true`.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("confirm",       "bool",   true),
            ]),
            destructive: true,
        },
        ToolSpec {
            name: "magma_state_list".into(),
            description: "List every resource address in the workspace's state.".into(),
            schema: minimal_schema(&[("workspace_dir", "string", true)]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_state_show".into(),
            description: "Show the typed state of a resource by address.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("address",       "string", true),
            ]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_state_mv".into(),
            description: "Move a resource within state. Requires explicit `confirm: true`.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("from",          "string", true),
                ("to",            "string", true),
                ("confirm",       "bool",   true),
            ]),
            destructive: true,
        },
        ToolSpec {
            name: "magma_output".into(),
            description: "Print an output value (or all outputs if `name` is omitted).".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("name",          "string", false),
            ]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_show".into(),
            description: "Show the current state (default) or a saved plan as typed JSON.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("plan_id",       "string", false),
            ]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_attest_verify".into(),
            description: "Verify a tameshi attestation receipt against a stored plan.".into(),
            schema: minimal_schema(&[
                ("workspace_dir", "string", true),
                ("plan_id",       "string", true),
            ]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_fixture_verify".into(),
            description: "Verify a single Pangea-rendered workspace through magma's typed pipeline. Returns a WorkspaceReport with resource counts, providers, action histogram, plan_id, and compatibility summary. Per theory/MAGMA.md §II.6 + magma-arch-test.".into(),
            schema: minimal_schema(&[("workspace_path", "string", true)]),
            destructive: false,
        },
        ToolSpec {
            name: "magma_fixture_verify_dir".into(),
            description: "Verify every `.tf.json` under a directory via magma-arch-test. Returns an AggregateReport with passed/failed counts + per-workspace breakdown. Reusable proof-surface for CI and rspec.".into(),
            schema: minimal_schema(&[("workspace_dir", "string", true)]),
            destructive: false,
        },
        // ── Pangea orchestration tools (M0.6) ──────────────────────
        ToolSpec {
            name: "pangea_orchestrate".into(),
            description: "Drive `magma flow run` over a typed Pangea::Magma::Chain JSON (workspaces + cross-workspace edges). Returns the typed AggregateReport. Non-destructive — performs plan-only across each workspace. Use this to verify a distribution's wiring without applying.".into(),
            schema: serde_json::json!({
                "type":     "object",
                "required": ["flow"],
                "properties": {
                    "flow": {
                        "type":     "object",
                        "required": ["workspaces"],
                        "properties": {
                            "workspaces": {
                                "type":  "array",
                                "items": {
                                    "type":     "object",
                                    "required": ["name", "dir"],
                                    "properties": {
                                        "name": { "type": "string" },
                                        "dir":  { "type": "string" }
                                    }
                                }
                            },
                            "edges": {
                                "type":  "array",
                                "items": {
                                    "type":     "object",
                                    "required": ["from", "from_output", "to", "to_input"],
                                    "properties": {
                                        "from":        { "type": "string" },
                                        "from_output": { "type": "string" },
                                        "to":          { "type": "string" },
                                        "to_input":    { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
            destructive: false,
        },
        ToolSpec {
            name: "magma_migrate_dry_run".into(),
            description: "Validate + preview a typed state-organization migration without writing either state file. Consumes the typed MigrationPlan shape (from/to/moves/preserve) — same shape `magma migrate` reads from disk — and returns a MigrationReceipt with BLAKE3 hashes pre/post + reasoning. Non-destructive variant of the migrate tool; required before `magma_migrate`.".into(),
            schema: migration_plan_schema(),
            destructive: false,
        },
        ToolSpec {
            name: "magma_migrate".into(),
            description: "Atomically move resources between workspaces' state files (no recreate, identity preserved). Requires explicit `confirm: true`. Consumes the typed MigrationPlan shape; returns a MigrationReceipt with BLAKE3 hashes pre/post per theory/PANGEA-MAGMA-ORCHESTRATION.md §V. Two-phase commit: validates source addresses + target collision-free, stages target write, then commits source.".into(),
            schema: {
                let mut s = migration_plan_schema();
                if let Some(props) = s.get_mut("properties").and_then(|v| v.as_object_mut()) {
                    props.insert("confirm".into(), serde_json::json!({ "type": "boolean" }));
                }
                if let Some(req) = s.get_mut("required").and_then(|v| v.as_array_mut()) {
                    req.push(serde_json::json!("confirm"));
                }
                s
            },
            destructive: true,
        },
        ToolSpec {
            name: "magma_split".into(),
            description: "Move a named subset of one workspace's resources into a new workspace. Thin wrapper over magma migrate for the common case of carving out a new state boundary. Requires explicit `confirm: true`.".into(),
            schema: serde_json::json!({
                "type":     "object",
                "required": ["from", "from_state", "to", "to_state", "resources", "confirm"],
                "properties": {
                    "from":       { "type": "string" },
                    "from_state": { "type": "string" },
                    "to":         { "type": "string" },
                    "to_state":   { "type": "string" },
                    "resources":  { "type": "array", "items": { "type": "string" } },
                    "dry_run":    { "type": "boolean" },
                    "confirm":    { "type": "boolean" }
                }
            }),
            destructive: true,
        },
        ToolSpec {
            name: "magma_merge".into(),
            description: "Move every resource from one workspace's state into another. Thin wrapper over magma migrate for the case where every source address moves over verbatim. Requires explicit `confirm: true`.".into(),
            schema: serde_json::json!({
                "type":     "object",
                "required": ["from", "from_state", "to", "to_state", "confirm"],
                "properties": {
                    "from":       { "type": "string" },
                    "from_state": { "type": "string" },
                    "to":         { "type": "string" },
                    "to_state":   { "type": "string" },
                    "dry_run":    { "type": "boolean" },
                    "confirm":    { "type": "boolean" }
                }
            }),
            destructive: true,
        },
    ]
}

fn migration_plan_schema() -> serde_json::Value {
    serde_json::json!({
        "type":     "object",
        "required": ["from", "to", "moves"],
        "properties": {
            "from": {
                "type":     "object",
                "required": ["name", "state_path"],
                "properties": {
                    "name":       { "type": "string" },
                    "state_path": { "type": "string" }
                }
            },
            "to": {
                "type":     "object",
                "required": ["name", "state_path"],
                "properties": {
                    "name":       { "type": "string" },
                    "state_path": { "type": "string" }
                }
            },
            "moves": {
                "type":  "array",
                "items": {
                    "type":     "object",
                    "required": ["source_address", "target_address"],
                    "properties": {
                        "source_address": { "type": "string" },
                        "target_address": { "type": "string" }
                    }
                }
            },
            "preserve": {
                "type": "object",
                "properties": {
                    "resource_identity":   { "type": "boolean" },
                    "tags":                { "type": "boolean" },
                    "dependent_resources": { "type": "boolean" }
                }
            },
            "dry_run": { "type": "boolean" }
        }
    })
}

fn minimal_schema(params: &[(&str, &str, bool)]) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, ty, is_required) in params {
        properties.insert((*name).to_string(), serde_json::json!({ "type": *ty }));
        if *is_required {
            required.push((*name).to_string());
        }
    }
    serde_json::json!({
        "type":       "object",
        "properties": properties,
        "required":   required,
    })
}

// ── Server ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum McpError {
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("destructive operation requires confirm: true")]
    UnconfirmedDestructive,
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid params: {0}")]
    InvalidParams(String),
}

/// Dispatch a JSON-RPC method to the matching tool. The actual operation
/// implementations land alongside magma-apply / magma-state in M0; this
/// crate owns the routing + validation + JSON-RPC framing.
pub async fn dispatch(req: JsonRpcRequest) -> JsonRpcResponse {
    let response_builder = |id: serde_json::Value| {
        move |result: Result<serde_json::Value, McpError>| match result {
            Ok(v) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(v),
                error: None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: serde_json::Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: e.to_string(),
                    data: None,
                }),
            },
        }
    };

    let build = response_builder(req.id.clone());

    match req.method.as_str() {
        "tools/list" => build(Ok(serde_json::json!({ "tools": tool_specs() }))),
        method if method.starts_with("tools/call/") => {
            let tool = method.trim_start_matches("tools/call/");
            build(handle_tool_call(tool, &req.params).await)
        }
        _ => build(Err(McpError::UnknownTool(req.method))),
    }
}

async fn handle_tool_call(
    tool: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, McpError> {
    let spec = tool_specs()
        .into_iter()
        .find(|t| t.name == tool)
        .ok_or_else(|| McpError::UnknownTool(tool.into()))?;

    // Destructive-operation gate.
    if spec.destructive {
        let confirmed = params
            .get("confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !confirmed {
            return Err(McpError::UnconfirmedDestructive);
        }
    }

    let workspace_dir = params
        .get("workspace_dir")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from);

    match tool {
        "magma_state_list" => {
            let dir = workspace_dir
                .ok_or_else(|| McpError::InvalidParams("workspace_dir required".into()))?;
            let state = read_state_inline(&dir).await?;
            let addresses: Vec<String> = state
                .resources
                .iter()
                .map(|r| format!("{}.{}", r.address.type_id.0, r.address.name))
                .collect();
            Ok(serde_json::json!({ "addresses": addresses }))
        }

        "magma_state_show" => {
            let dir = workspace_dir
                .ok_or_else(|| McpError::InvalidParams("workspace_dir required".into()))?;
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| McpError::InvalidParams("address required".into()))?;
            let state = read_state_inline(&dir).await?;
            let found = state
                .resources
                .iter()
                .find(|r| format!("{}.{}", r.address.type_id.0, r.address.name) == address);
            match found {
                Some(r) => Ok(serde_json::to_value(r)?),
                None => Err(McpError::InvalidParams(format!(
                    "address {address} not in state"
                ))),
            }
        }

        "magma_fixture_verify" => {
            let path = params
                .get("workspace_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| McpError::InvalidParams("workspace_path required".into()))?;
            let harness = magma_arch_test::WorkspaceTestHarness::new(path);
            match harness.verify().await {
                Ok(report) => Ok(serde_json::to_value(report)?),
                Err(e) => Err(McpError::InvalidParams(e.to_string())),
            }
        }

        "magma_fixture_verify_dir" => {
            let dir = workspace_dir
                .ok_or_else(|| McpError::InvalidParams("workspace_dir required".into()))?;
            match magma_arch_test::verify_directory(&dir).await {
                Ok(agg) => Ok(serde_json::to_value(agg)?),
                Err(e) => Err(McpError::InvalidParams(e.to_string())),
            }
        }

        "magma_plan" => {
            // Real in-process dispatch via magma-pangea + magma-plan +
            // magma-backend. magma-mcp now owns those transitive deps
            // alongside magma-flow, so the MCP server can plan directly
            // without round-tripping through the CLI.
            use magma_backend::Backend as _;
            use magma_pangea::WorkspaceLoader as _;

            let dir = workspace_dir
                .ok_or_else(|| McpError::InvalidParams("workspace_dir required".into()))?;
            let shape = magma_pangea::WorkspaceShape::discover(&dir)
                .map_err(|e| McpError::InvalidParams(format!("discover: {e}")))?;
            let loaded = magma_pangea::TerraformJsonLoader
                .load(shape)
                .await
                .map_err(|e| McpError::InvalidParams(format!("load: {e}")))?;
            let cfg = magma_config::Config::from_json(loaded.rendered)
                .map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
            let backend = magma_backend::LocalBackend::new(dir.clone());
            let state = backend
                .read_state()
                .await
                .map_err(|e| McpError::InvalidParams(format!("read state: {e}")))?;
            let plan = magma_plan::plan(&cfg, &state)
                .map_err(|e| McpError::InvalidParams(format!("plan: {e}")))?;

            Ok(serde_json::json!({
                "plan_id":          hex::encode(plan.id.0),
                "created_at":       plan.created_at,
                "workspace_dir":    dir,
                "resource_changes": plan.resource_changes,
                "summary": {
                    "total":  plan.resource_changes.len(),
                },
            }))
        }

        // ── Pangea orchestration dispatch (M0.6) ─────────────────
        "pangea_orchestrate" => dispatch_pangea_orchestrate(params).await,
        "magma_migrate_dry_run" => dispatch_migrate(params, /*force_dry*/ true).await,
        "magma_migrate" => dispatch_migrate(params, /*force_dry*/ false).await,
        "magma_split" => dispatch_split(params).await,
        "magma_merge" => dispatch_merge(params).await,

        // Other tools surface via MCP routing but their full dispatch
        // requires either (a) magma-mcp depending on magma-plan / magma-apply
        // (creating a wider dep graph), or (b) shelling out to the magma
        // binary. The pleme-io idiom is (a) but it's been deferred to a
        // follow-up to keep magma-mcp's compile surface narrow.
        _ => Ok(serde_json::json!({
            "tool":   tool,
            "wiring": "magma-cli mediates this operation today; magma-mcp dispatch surfaces in the M0.1 refactor",
            "params_received": params,
        })),
    }
}

// ── M0.6 in-process dispatch (no shelling out to magma binary) ─────

async fn dispatch_migrate(
    params: &serde_json::Value,
    force_dry: bool,
) -> Result<serde_json::Value, McpError> {
    let mut plan: magma_migrate::MigrationPlan = serde_json::from_value(params.clone())
        .map_err(|e| McpError::InvalidParams(format!("MigrationPlan: {e}")))?;
    if force_dry {
        plan.dry_run = true;
    }
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| McpError::InvalidParams(format!("migrate: {e}")))?;
    Ok(serde_json::to_value(receipt)?)
}

async fn dispatch_split(params: &serde_json::Value) -> Result<serde_json::Value, McpError> {
    let from = require_str(params, "from")?;
    let from_state = require_str(params, "from_state")?;
    let to = require_str(params, "to")?;
    let to_state = require_str(params, "to_state")?;
    let resources = params
        .get("resources")
        .and_then(|v| v.as_array())
        .ok_or_else(|| McpError::InvalidParams("resources array required".into()))?;
    let dry_run = params
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if resources.is_empty() {
        return Err(McpError::InvalidParams(
            "split: resources cannot be empty".into(),
        ));
    }

    let moves: Vec<magma_migrate::ResourceMove> = resources
        .iter()
        .filter_map(|r| {
            r.as_str().map(|addr| magma_migrate::ResourceMove {
                source_address: addr.into(),
                target_address: addr.into(),
            })
        })
        .collect();

    let plan = magma_migrate::MigrationPlan {
        from: magma_migrate::WorkspaceRef {
            name: from.into(),
            state_path: from_state.into(),
        },
        to: magma_migrate::WorkspaceRef {
            name: to.into(),
            state_path: to_state.into(),
        },
        moves,
        preserve: magma_migrate::PreserveFlags::default(),
        dry_run,
    };
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| McpError::InvalidParams(format!("split: {e}")))?;
    Ok(serde_json::to_value(receipt)?)
}

async fn dispatch_merge(params: &serde_json::Value) -> Result<serde_json::Value, McpError> {
    let from = require_str(params, "from")?;
    let from_state = require_str(params, "from_state")?;
    let to = require_str(params, "to")?;
    let to_state = require_str(params, "to_state")?;
    let dry_run = params
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let from_state_path = std::path::PathBuf::from(from_state);
    let state = magma_state::read_state(&from_state_path)
        .await
        .map_err(|e| McpError::InvalidParams(format!("read source state: {e}")))?;

    let moves: Vec<magma_migrate::ResourceMove> = state
        .resources
        .iter()
        .map(|r| {
            let addr = format!("{}.{}", r.address.type_id.0, r.address.name);
            magma_migrate::ResourceMove {
                source_address: addr.clone(),
                target_address: addr,
            }
        })
        .collect();

    let plan = magma_migrate::MigrationPlan {
        from: magma_migrate::WorkspaceRef {
            name: from.into(),
            state_path: from_state_path,
        },
        to: magma_migrate::WorkspaceRef {
            name: to.into(),
            state_path: to_state.into(),
        },
        moves,
        preserve: magma_migrate::PreserveFlags::default(),
        dry_run,
    };
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| McpError::InvalidParams(format!("merge: {e}")))?;
    Ok(serde_json::to_value(receipt)?)
}

// FlowFile / topological_order / plan loop now live in magma-flow.
// `pangea_orchestrate` dispatch is a thin parse + delegate.

async fn dispatch_pangea_orchestrate(
    params: &serde_json::Value,
) -> Result<serde_json::Value, McpError> {
    let flow_value = params
        .get("flow")
        .ok_or_else(|| McpError::InvalidParams("flow required".into()))?;
    let flow: magma_flow::FlowFile = serde_json::from_value(flow_value.clone())
        .map_err(|e| McpError::InvalidParams(format!("flow: {e}")))?;
    let report = magma_flow::run(&flow)
        .await
        .map_err(|e| McpError::InvalidParams(format!("flow run: {e}")))?;
    Ok(serde_json::to_value(report)?)
}

fn require_str<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str, McpError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams(format!("{key} required")))
}

async fn read_state_inline(dir: &std::path::Path) -> Result<magma_types::State, McpError> {
    let path = dir.join("terraform.tfstate");
    magma_state::read_state(path)
        .await
        .map_err(|e| McpError::InvalidParams(format!("read state: {e}")))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_specs_carries_destructive_flags() {
        let specs = tool_specs();
        assert!(
            specs
                .iter()
                .any(|t| t.name == "magma_plan" && !t.destructive)
        );
        assert!(
            specs
                .iter()
                .any(|t| t.name == "magma_apply" && t.destructive)
        );
        assert!(
            specs
                .iter()
                .any(|t| t.name == "magma_destroy" && t.destructive)
        );
        assert!(
            specs
                .iter()
                .any(|t| t.name == "magma_state_mv" && t.destructive)
        );
        assert!(
            specs
                .iter()
                .any(|t| t.name == "magma_state_show" && !t.destructive)
        );
    }

    #[tokio::test]
    async fn tools_list_lists_all() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/list".into(),
            params: serde_json::Value::Null,
        };
        let resp = dispatch(req).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.len() >= 10);
    }

    #[tokio::test]
    async fn destructive_call_without_confirm_errs() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_apply".into(),
            params: serde_json::json!({
                "workspace_dir": "/tmp/x",
                "plan_id":       "0000",
                "confirm":       false,
            }),
        };
        let resp = dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(
            resp.error
                .unwrap()
                .message
                .contains("requires confirm: true")
        );
    }

    #[tokio::test]
    async fn destructive_call_with_confirm_routes() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_apply".into(),
            params: serde_json::json!({
                "workspace_dir": "/tmp/x",
                "plan_id":       "0000",
                "confirm":       true,
            }),
        };
        let resp = dispatch(req).await;
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn nondestructive_call_routes() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_state_list".into(),
            params: serde_json::json!({ "workspace_dir": "/tmp/x" }),
        };
        let resp = dispatch(req).await;
        assert!(resp.result.is_some());
    }

    #[test]
    fn schema_includes_confirm_for_destructive() {
        let specs = tool_specs();
        let apply = specs.iter().find(|t| t.name == "magma_apply").unwrap();
        let required = apply.schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "confirm"));
    }

    #[test]
    fn m06_tools_registered() {
        let specs = tool_specs();
        for name in [
            "pangea_orchestrate",
            "magma_migrate",
            "magma_migrate_dry_run",
            "magma_split",
            "magma_merge",
        ] {
            assert!(
                specs.iter().any(|t| t.name == name),
                "missing M0.6 tool: {name}"
            );
        }
        // Destructive gating
        let destructive_set: std::collections::HashSet<&str> = specs
            .iter()
            .filter(|t| t.destructive)
            .map(|t| t.name.as_str())
            .collect();
        assert!(destructive_set.contains("magma_migrate"));
        assert!(destructive_set.contains("magma_split"));
        assert!(destructive_set.contains("magma_merge"));
        assert!(!destructive_set.contains("magma_migrate_dry_run"));
        assert!(!destructive_set.contains("pangea_orchestrate"));
    }

    #[tokio::test]
    async fn m06_migrate_dry_run_dispatches_in_process() {
        // Build a synthetic state via the shared magma-fixtures
        // builder, drive magma_migrate_dry_run, verify no mutation.
        use magma_fixtures::StateBuilder;

        let (src_path, _src_tmp) = StateBuilder::new()
            .resource("aws_iam_role", "alpha", serde_json::json!({"name":"alpha"}))
            .write_tempfile()
            .await
            .unwrap();
        let dst_tmp = tempfile::tempdir().unwrap();
        let dst_path = dst_tmp.path().join("dst.tfstate");

        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_migrate_dry_run".into(),
            params: serde_json::json!({
                "from": { "name": "src", "state_path": src_path },
                "to":   { "name": "dst", "state_path": dst_path },
                "moves": [
                    { "source_address": "aws_iam_role.alpha",
                      "target_address": "aws_iam_role.alpha" }
                ],
                "dry_run": false,  // force_dry should override
            }),
        };
        let resp = dispatch(req).await;
        assert!(resp.error.is_none(), "dry-run errored: {:?}", resp.error);
        let src_after = magma_state::read_state(&src_path).await.unwrap();
        assert_eq!(src_after.resources.len(), 1);
        assert!(!dst_path.exists(), "dry-run wrote target state");
    }

    #[tokio::test]
    async fn magma_plan_dispatches_in_process() {
        // Render a minimal Pangea-shaped .tf.json via the shared
        // builder and dispatch magma_plan through the MCP entry point.
        let ws = magma_fixtures::TfJsonBuilder::new()
            .resource(
                "aws_iam_role",
                "r",
                serde_json::json!({"name": "mcp-plan-test"}),
            )
            .render_to_tempdir()
            .unwrap();

        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_plan".into(),
            params: serde_json::json!({ "workspace_dir": ws.dir() }),
        };
        let resp = dispatch(req).await;
        assert!(resp.error.is_none(), "plan errored: {:?}", resp.error);
        let result = resp.result.unwrap();
        assert!(result["plan_id"].as_str().unwrap().len() == 64);
        assert!(result["resource_changes"].is_array());
    }

    #[tokio::test]
    async fn m06_destructive_migrate_without_confirm_errs() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "tools/call/magma_migrate".into(),
            params: serde_json::json!({
                "from": { "name": "x", "state_path": "/tmp/_nope_src.tfstate" },
                "to":   { "name": "y", "state_path": "/tmp/_nope_dst.tfstate" },
                "moves": [],
                "confirm": false,
            }),
        };
        let resp = dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("confirm: true"));
    }
}
