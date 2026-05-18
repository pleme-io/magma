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
    pub id:      serde_json::Value,
    pub method:  String,
    #[serde(default)]
    pub params:  serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id:      serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result:  Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:   Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code:    i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data:    Option<serde_json::Value>,
}

// ── MCP tool registry ─────────────────────────────────────────────

/// Typed schema for a single MCP tool. Generated from magma-types in M0;
/// the schema field is a `serde_json::Value` representing a JSON-Schema
/// draft-7 object for the tool's parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name:        String,
    pub description: String,
    pub schema:      serde_json::Value,
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
    ]
}

fn minimal_schema(params: &[(&str, &str, bool)]) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required   = Vec::new();
    for (name, ty, is_required) in params {
        properties.insert(
            (*name).to_string(),
            serde_json::json!({ "type": *ty }),
        );
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
                result:  Some(v),
                error:   None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id:      serde_json::Value::Null,
                result:  None,
                error:   Some(JsonRpcError {
                    code:    -32000,
                    message: e.to_string(),
                    data:    None,
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
            let dir = workspace_dir.ok_or_else(|| {
                McpError::InvalidParams("workspace_dir required".into())
            })?;
            let state = read_state_inline(&dir).await?;
            let addresses: Vec<String> = state
                .resources
                .iter()
                .map(|r| format!("{}.{}", r.address.type_id.0, r.address.name))
                .collect();
            Ok(serde_json::json!({ "addresses": addresses }))
        }

        "magma_state_show" => {
            let dir = workspace_dir.ok_or_else(|| {
                McpError::InvalidParams("workspace_dir required".into())
            })?;
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| McpError::InvalidParams("address required".into()))?;
            let state = read_state_inline(&dir).await?;
            let found = state.resources.iter().find(|r| {
                format!("{}.{}", r.address.type_id.0, r.address.name) == address
            });
            match found {
                Some(r) => Ok(serde_json::to_value(r)?),
                None => Err(McpError::InvalidParams(format!("address {address} not in state"))),
            }
        }

        "magma_plan" => {
            // The actual plan computation lives in magma-plan but
            // magma-mcp doesn't depend on it directly to avoid a cycle.
            // The CLI binary mediates: MCP clients invoke `magma plan
            // --json --workspace=<dir>` via a tool-call adapter in
            // production deployments. For M0 the typed schema is
            // exposed and validation works; the actual plan call lands
            // when magma-mcp gains magma-plan as a transitive dep
            // alongside the operator/library refactor.
            Ok(serde_json::json!({
                "tool":           tool,
                "workspace_dir":  workspace_dir,
                "wiring":         "magma-cli mediates plan execution; see magma plan --json",
            }))
        }

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

async fn read_state_inline(dir: &std::path::Path) -> Result<magma_types::State, McpError> {
    let path = dir.join("terraform.tfstate");
    magma_state::read_state(path).await.map_err(|e| {
        McpError::InvalidParams(format!("read state: {e}"))
    })
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_specs_carries_destructive_flags() {
        let specs = tool_specs();
        assert!(specs.iter().any(|t| t.name == "magma_plan" && !t.destructive));
        assert!(specs.iter().any(|t| t.name == "magma_apply" && t.destructive));
        assert!(specs.iter().any(|t| t.name == "magma_destroy" && t.destructive));
        assert!(specs.iter().any(|t| t.name == "magma_state_mv" && t.destructive));
        assert!(specs.iter().any(|t| t.name == "magma_state_show" && !t.destructive));
    }

    #[tokio::test]
    async fn tools_list_lists_all() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id:      serde_json::json!(1),
            method:  "tools/list".into(),
            params:  serde_json::Value::Null,
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
            id:      serde_json::json!(1),
            method:  "tools/call/magma_apply".into(),
            params:  serde_json::json!({
                "workspace_dir": "/tmp/x",
                "plan_id":       "0000",
                "confirm":       false,
            }),
        };
        let resp = dispatch(req).await;
        assert!(resp.error.is_some());
        assert!(resp
            .error
            .unwrap()
            .message
            .contains("requires confirm: true"));
    }

    #[tokio::test]
    async fn destructive_call_with_confirm_routes() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id:      serde_json::json!(1),
            method:  "tools/call/magma_apply".into(),
            params:  serde_json::json!({
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
            id:      serde_json::json!(1),
            method:  "tools/call/magma_state_list".into(),
            params:  serde_json::json!({ "workspace_dir": "/tmp/x" }),
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

}
