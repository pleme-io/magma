//! magma-plugin::import — the typed `ImportResourceState` gRPC client
//! call.
//!
//! This is the missing keystone of magma's adopt-a-pre-existing-resource
//! capability. Given a dialed provider channel, a resource `type_name`,
//! and a provider-specific `id`, it drives the provider's
//! `ImportResourceState` RPC and decodes each returned `DynamicValue`
//! state into typed `magma_types::ImportedInstance` values.
//!
//! It follows the exact RPC-call pattern the lifecycle integration
//! tests use for `PlanResourceChange` / `ApplyResourceChange`:
//! `ProviderClient::new(channel)` then `client.method(req).await`. The
//! `DynamicValue` decode uses the same `json`-field path
//! `PlanResourceChange` uses on the wire (magma has no msgpack decoder;
//! a state that arrives only as msgpack surfaces a typed error rather
//! than a silent wrong answer).

use magma_protocol::tfplugin6;
use magma_protocol::tfplugin6::provider_client::ProviderClient;
use magma_types::ImportedInstance;

use crate::{H2Channel, PluginError};

/// Decode a tfplugin6 `DynamicValue` into a typed `serde_json::Value`.
///
/// magma's wire path uses the `json` field (the same field
/// `PlanResourceChange`/`ApplyResourceChange` round-trip in the
/// lifecycle integration suite). A `DynamicValue` carrying ONLY
/// msgpack surfaces a typed error — magma has no msgpack decoder yet,
/// and a silent wrong answer is forbidden (theory/MAGMA.md §IX +
/// the TYPED-SPEC rule).
fn decode_dynamic_value(dv: &tfplugin6::DynamicValue) -> Result<serde_json::Value, PluginError> {
    if !dv.json.is_empty() {
        return serde_json::from_slice(&dv.json).map_err(|e| {
            PluginError::ImportDecode(format!("DynamicValue.json is not valid JSON: {e}"))
        });
    }
    if !dv.msgpack.is_empty() {
        return Err(PluginError::ImportDecode(
            "provider returned imported state as msgpack only; magma's wire decoder \
             reads the DynamicValue.json field (no msgpack decoder yet)"
                .into(),
        ));
    }
    // An empty DynamicValue is a legitimate "null" state — decode to
    // JSON null so the caller absorbs an empty-attributes instance
    // rather than erroring.
    Ok(serde_json::Value::Null)
}

/// Render the provider's `Diagnostic` list into one error string. Only
/// `ERROR`-severity diagnostics are fatal; warnings/info are dropped
/// (they don't fail an import).
fn fatal_diagnostics(diags: &[tfplugin6::Diagnostic]) -> Option<String> {
    let errors: Vec<String> = diags
        .iter()
        .filter(|d| d.severity == tfplugin6::diagnostic::Severity::Error as i32)
        .map(|d| {
            if d.detail.is_empty() {
                d.summary.clone()
            } else {
                format!("{}: {}", d.summary, d.detail)
            }
        })
        .collect();
    if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    }
}

/// Drive the provider's `ImportResourceState` RPC for `(type_name, id)`
/// over a dialed gRPC `channel`, returning the typed imported
/// resources.
///
/// This is the in-process equivalent of `tofu import <addr> <id>`: it
/// asks the provider "given this id, what is the live resource's
/// state?" and hands back the decoded attributes the apply prepass
/// absorbs into the working state.
///
/// # Errors
///
/// * `PluginError::ImportRpc` — the gRPC call itself failed (transport
///   error, provider crashed, etc.).
/// * `PluginError::ImportRejected` — the provider returned ERROR-level
///   diagnostics (bad id, resource not found, type doesn't support
///   import).
/// * `PluginError::ImportDecode` — a returned `DynamicValue` couldn't
///   be decoded via the json path.
pub async fn import_resource_state(
    channel: H2Channel,
    type_name: &str,
    id: &str,
) -> Result<Vec<ImportedInstance>, PluginError> {
    let mut client = ProviderClient::new(channel);

    let req = tfplugin6::import_resource_state::Request {
        type_name: type_name.to_string(),
        id: id.to_string(),
        client_capabilities: crate::provider::client_caps_v6(),
        identity: None,
    };

    let resp = client
        .import_resource_state(req)
        .await
        .map_err(|status| {
            PluginError::ImportRpc(format!(
                "ImportResourceState RPC for {type_name} id={id:?} failed: {status}"
            ))
        })?
        .into_inner();

    if let Some(reason) = fatal_diagnostics(&resp.diagnostics) {
        return Err(PluginError::ImportRejected {
            type_name: type_name.to_string(),
            id: id.to_string(),
            reason,
        });
    }

    let mut imported = Vec::with_capacity(resp.imported_resources.len());
    for res in resp.imported_resources {
        let attributes = match res.state.as_ref() {
            Some(dv) => decode_dynamic_value(dv)?,
            None => serde_json::Value::Null,
        };
        imported.push(ImportedInstance {
            type_name: res.type_name,
            attributes,
            private: res.private,
        });
    }

    Ok(imported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_json_dynamic_value() {
        let dv = tfplugin6::DynamicValue {
            msgpack: vec![],
            json: br#"{"id":"role-1","name":"cluster-role"}"#.to_vec(),
        };
        let v = decode_dynamic_value(&dv).unwrap();
        assert_eq!(v["id"], "role-1");
        assert_eq!(v["name"], "cluster-role");
    }

    #[test]
    fn decode_empty_dynamic_value_is_null() {
        let dv = tfplugin6::DynamicValue {
            msgpack: vec![],
            json: vec![],
        };
        assert_eq!(decode_dynamic_value(&dv).unwrap(), serde_json::Value::Null);
    }

    #[test]
    fn decode_msgpack_only_is_typed_error() {
        let dv = tfplugin6::DynamicValue {
            msgpack: vec![0x81, 0xa2, 0x69, 0x64],
            json: vec![],
        };
        assert!(matches!(
            decode_dynamic_value(&dv),
            Err(PluginError::ImportDecode(_))
        ));
    }

    #[test]
    fn fatal_diagnostics_extracts_errors_only() {
        let diags = vec![
            tfplugin6::Diagnostic {
                severity: tfplugin6::diagnostic::Severity::Warning as i32,
                summary: "a warning".into(),
                detail: String::new(),
                attribute: None,
            },
            tfplugin6::Diagnostic {
                severity: tfplugin6::diagnostic::Severity::Error as i32,
                summary: "bad id".into(),
                detail: "no such resource".into(),
                attribute: None,
            },
        ];
        let reason = fatal_diagnostics(&diags).unwrap();
        assert!(reason.contains("bad id"));
        assert!(reason.contains("no such resource"));
        assert!(!reason.contains("a warning"));
    }

    #[test]
    fn no_fatal_diagnostics_when_all_warnings() {
        let diags = vec![tfplugin6::Diagnostic {
            severity: tfplugin6::diagnostic::Severity::Warning as i32,
            summary: "just a warning".into(),
            detail: String::new(),
            attribute: None,
        }];
        assert!(fatal_diagnostics(&diags).is_none());
    }
}
