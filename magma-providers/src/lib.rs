//! magma-providers — provider discovery + a live `ProviderRegistry`.
//!
//! Resolves provider binaries from the terraform plugin cache
//! (`~/.terraform.d/plugin-cache/<registry>/<ns>/<name>/<ver>/<os_arch>/`),
//! spawns + caches them via `magma-plugin`, and exposes the
//! provider-RPC surface the apply engine needs: `configure`,
//! `plan_create`, `apply_create`. RPCs are dispatched by the protocol
//! negotiated in the go-plugin handshake — NEVER by the provider's
//! marketing version (e.g. `integrations/github` v6.x speaks
//! **protocol v5** because it is an SDKv2 provider).
//!
//! # Wire encoding
//!
//! Provider config/state cross the gRPC boundary as a tfplugin
//! `DynamicValue`, which carries EITHER a msgpack OR a json payload.
//! We SEND json (`serde_json` → bytes; the provider type-coerces it
//! against its schema — no client-side cty encoder needed). Providers
//! RESPOND in msgpack, so reading attributes back into typed state goes
//! through [`decode_dynamic_value_msgpack`].
//!
//! # Scope
//!
//! Protocol v5 (terraform-plugin-sdk v2 — null, github, aws, …, the
//! overwhelming majority of the registry) is fully wired. Protocol v6
//! (terraform-plugin-framework) returns a typed
//! [`ProviderError::UnsupportedProtocol`] rather than a silent stub —
//! it lands when a v6 provider first appears on a real workload (per the
//! no-silent-wrong-answers discipline).
//!
//! Registry download (resolving a provider that is NOT yet in the local
//! cache, from the OpenTofu/Terraform registry) is the next layer; today
//! the cache must be pre-populated (`tofu init`). The resolver errors
//! loudly with [`ProviderError::NotFound`] when a provider is absent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use magma_plugin::{Plugin, PluginSpec};
use magma_protocol::{tfplugin5, PluginProtocol};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;
use tonic::transport::Channel;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider `{provider}` not found in plugin cache {cache:?} for {os_arch}")]
    NotFound {
        provider: String,
        cache: PathBuf,
        os_arch: String,
    },
    #[error("plugin spawn/dial failed: {0}")]
    Plugin(#[from] magma_plugin::PluginError),
    #[error("provider RPC `{rpc}` transport error: {status}")]
    Rpc { rpc: &'static str, status: String },
    #[error("provider returned error diagnostics on `{rpc}`: {diags}")]
    Diagnostics { rpc: &'static str, diags: String },
    #[error("provider `{rpc}` returned an empty {what}")]
    EmptyResponse { rpc: &'static str, what: &'static str },
    #[error("decode provider msgpack response: {0}")]
    Decode(String),
    #[error("encode provider json config: {0}")]
    Encode(String),
    #[error(
        "provider speaks protocol {0:?} — only v5 (terraform-plugin-sdk) is wired today; \
         v6 (terraform-plugin-framework) support lands when a v6 workload first needs it"
    )]
    UnsupportedProtocol(PluginProtocol),
}

// ── DynamicValue msgpack decode ────────────────────────────────────

/// Decode a provider's msgpack-encoded `DynamicValue` payload into a
/// `serde_json::Value`. Providers respond in cty msgpack; a fully-applied
/// resource carries only concrete values (no unknown markers), so the
/// `rmpv` value maps cleanly. `rmpv` (not `rmp-serde`) is used so cty
/// ext-types degrade to `Null` instead of erroring the whole decode.
pub fn decode_dynamic_value_msgpack(bytes: &[u8]) -> Result<Value, ProviderError> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    let mut cur = std::io::Cursor::new(bytes);
    let v = rmpv::decode::read_value(&mut cur)
        .map_err(|e| ProviderError::Decode(e.to_string()))?;
    rmpv_to_json(v)
}

fn rmpv_to_json(v: rmpv::Value) -> Result<Value, ProviderError> {
    use rmpv::Value as R;
    Ok(match v {
        R::Nil => Value::Null,
        R::Boolean(b) => Value::Bool(b),
        R::Integer(i) => {
            if let Some(u) = i.as_u64() {
                Value::from(u)
            } else if let Some(s) = i.as_i64() {
                Value::from(s)
            } else {
                Value::Null
            }
        }
        R::F32(f) => serde_json::Number::from_f64(f64::from(f)).map_or(Value::Null, Value::Number),
        R::F64(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        R::String(s) => Value::String(s.into_str().unwrap_or_default()),
        R::Binary(b) => Value::Array(b.into_iter().map(Value::from).collect()),
        R::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for item in a {
                out.push(rmpv_to_json(item)?);
            }
            Value::Array(out)
        }
        R::Map(m) => {
            let mut obj = serde_json::Map::with_capacity(m.len());
            for (k, val) in m {
                let key = match k {
                    R::String(s) => s.into_str().unwrap_or_default(),
                    other => {
                        return Err(ProviderError::Decode(format!(
                            "non-string msgpack map key: {other:?}"
                        )));
                    }
                };
                obj.insert(key, rmpv_to_json(val)?);
            }
            Value::Object(obj)
        }
        // cty unknown / refinement markers — never present in applied state.
        R::Ext(_, _) => Value::Null,
    })
}

// ── Planned change (opaque carry from plan → apply) ────────────────

/// The provider's planned new state, carried verbatim from
/// `plan_create` into `apply_create`. The provider validates that the
/// `planned_state` it receives in ApplyResourceChange is byte-identical
/// to what it returned from PlanResourceChange, so this is passed
/// through unchanged (both wire encodings + the private blob).
#[derive(Debug, Clone, Default)]
pub struct PlannedCreate {
    planned_state_msgpack: Vec<u8>,
    planned_state_json: Vec<u8>,
    planned_private: Vec<u8>,
}

// ── Registry ───────────────────────────────────────────────────────

struct RegistryState {
    /// Spawned plugins, kept alive for the registry's lifetime (Drop
    /// SIGTERMs the child). Held here rather than inside `conns` because
    /// `tokio::process::Child` is `!Sync` — sharing only the (Send+Sync)
    /// `Channel` keeps `ProviderConn` cheaply `Clone` + thread-safe.
    plugins: Vec<Plugin>,
    /// source ("ns/name") → live connection.
    conns: HashMap<String, ProviderConn>,
}

/// Resolve + spawn + cache provider plugins; hand out [`ProviderConn`]s.
pub struct ProviderRegistry {
    plugin_cache: PathBuf,
    state: Mutex<RegistryState>,
}

impl ProviderRegistry {
    /// Build a registry over an explicit plugin-cache root.
    #[must_use]
    pub fn new(plugin_cache: impl Into<PathBuf>) -> Self {
        Self {
            plugin_cache: plugin_cache.into(),
            state: Mutex::new(RegistryState {
                plugins: Vec::new(),
                conns: HashMap::new(),
            }),
        }
    }

    /// Build a registry over the default terraform plugin cache.
    ///
    /// Honors `TF_PLUGIN_CACHE_DIR` (the standard terraform env) first —
    /// so a Nix-built image can point the registry at a store path that
    /// bundles the provider binaries (e.g.
    /// `${terraform-providers.github}/libexec/terraform-providers`)
    /// without any `$HOME` juggling — then falls back to
    /// `$HOME/.terraform.d/plugin-cache`.
    #[must_use]
    pub fn from_default_cache() -> Self {
        if let Ok(dir) = std::env::var("TF_PLUGIN_CACHE_DIR") {
            if !dir.is_empty() {
                return Self::new(dir);
            }
        }
        let home = std::env::var("HOME").unwrap_or_default();
        Self::new(PathBuf::from(home).join(".terraform.d/plugin-cache"))
    }

    /// Resolve a provider binary from the plugin cache by source
    /// (`"namespace/name"`, e.g. `"integrations/github"`; a bare name is
    /// treated as `hashicorp/<name>`). Picks the highest version dir for
    /// the current `os_arch`.
    pub fn resolve(&self, source: &str) -> Result<PathBuf, ProviderError> {
        let (ns, name) = source.split_once('/').unwrap_or(("hashicorp", source));
        let os_arch = current_os_arch();
        for registry in read_subdirs(&self.plugin_cache) {
            let base = registry.join(ns).join(name);
            let mut versions = read_subdirs(&base);
            // Highest version first. Lexical sort is correct for the
            // common semver dirs we see in practice; a full semver
            // compare is a later refinement.
            versions.sort();
            for ver in versions.into_iter().rev() {
                let arch_dir = ver.join(&os_arch);
                if let Some(bin) = find_provider_binary(&arch_dir, name) {
                    return Ok(bin);
                }
            }
        }
        Err(ProviderError::NotFound {
            provider: source.to_string(),
            cache: self.plugin_cache.clone(),
            os_arch,
        })
    }

    /// Get (spawning + caching on first use) a live connection to the
    /// provider for `source`. Subsequent calls return the same
    /// connection — the provider process + gRPC channel are reused.
    pub async fn connect(&self, source: &str) -> Result<ProviderConn, ProviderError> {
        // Cache first: a connection pre-seeded via `connect_binary` (or a
        // prior `connect`) is reused without touching the plugin cache —
        // so callers can register a provider by an explicit path under a
        // source key and have `connect(source)` resolve to it.
        {
            let st = self.state.lock().await;
            if let Some(c) = st.conns.get(source) {
                return Ok(c.clone());
            }
        }
        let binary = self.resolve(source)?;
        self.connect_binary(source, binary).await
    }

    /// Like [`connect`](Self::connect) but spawns an explicit binary,
    /// bypassing cache resolution. Used when the caller already knows the
    /// provider path (tests; a future lock-file-pinned path) — the
    /// `source` label is still the connection cache key.
    pub async fn connect_binary(
        &self,
        source: &str,
        binary: PathBuf,
    ) -> Result<ProviderConn, ProviderError> {
        let mut st = self.state.lock().await;
        if let Some(c) = st.conns.get(source) {
            return Ok(c.clone());
        }
        let mut plugin = Plugin::spawn(PluginSpec {
            binary,
            ..Default::default()
        })
        .await?;
        let protocol = plugin.handshake().app_protocol;
        let channel = plugin.dial().await?.clone();
        let conn = ProviderConn {
            channel,
            protocol,
            source: Arc::from(source),
        };
        st.plugins.push(plugin);
        st.conns.insert(source.to_string(), conn.clone());
        Ok(conn)
    }
}

// ── Connection (the per-provider RPC surface) ──────────────────────

/// A live gRPC connection to one provider process. Cheaply `Clone`
/// (shares the underlying channel). RPCs dispatch by the negotiated
/// `protocol`.
#[derive(Clone)]
pub struct ProviderConn {
    channel: Channel,
    protocol: PluginProtocol,
    source: Arc<str>,
}

impl ProviderConn {
    /// The protocol the provider negotiated in its handshake.
    #[must_use]
    pub fn protocol(&self) -> PluginProtocol {
        self.protocol
    }

    /// The provider source this connection serves (`"ns/name"`).
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The resource type names this provider exposes (schema keys). Used
    /// for capability checks + tests.
    pub async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        match self.protocol {
            PluginProtocol::V5 => {
                let mut c = self.v5();
                let resp = c
                    .get_schema(tfplugin5::get_provider_schema::Request {})
                    .await
                    .map_err(|s| ProviderError::Rpc {
                        rpc: "get_schema",
                        status: s.to_string(),
                    })?
                    .into_inner();
                check_v5_diags("get_schema", &resp.diagnostics)?;
                Ok(resp.resource_schemas.into_keys().collect())
            }
            other => Err(ProviderError::UnsupportedProtocol(other)),
        }
    }

    /// `ConfigureProvider` — pass the provider-level config (e.g. the
    /// github token). Empty object `{}` for providers that need none.
    pub async fn configure(&self, config: &Value) -> Result<(), ProviderError> {
        let json = to_json_bytes(config)?;
        match self.protocol {
            PluginProtocol::V5 => {
                let mut c = self.v5();
                let resp = c
                    .configure(tfplugin5::configure::Request {
                        terraform_version: "1.7.0".into(),
                        config: Some(tfplugin5::DynamicValue {
                            msgpack: vec![],
                            json,
                        }),
                        client_capabilities: None,
                    })
                    .await
                    .map_err(|s| ProviderError::Rpc {
                        rpc: "configure",
                        status: s.to_string(),
                    })?
                    .into_inner();
                check_v5_diags("configure", &resp.diagnostics)
            }
            other => Err(ProviderError::UnsupportedProtocol(other)),
        }
    }

    /// `PlanResourceChange` for a fresh resource (prior state = null).
    /// Returns the provider's planned new state, carried verbatim into
    /// [`apply_create`](Self::apply_create).
    pub async fn plan_create(
        &self,
        type_name: &str,
        config: &Value,
    ) -> Result<PlannedCreate, ProviderError> {
        let json = to_json_bytes(config)?;
        match self.protocol {
            PluginProtocol::V5 => {
                let mut c = self.v5();
                let resp = c
                    .plan_resource_change(tfplugin5::plan_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(null_dynamic_value_v5()),
                        proposed_new_state: Some(tfplugin5::DynamicValue {
                            msgpack: vec![],
                            json: json.clone(),
                        }),
                        config: Some(tfplugin5::DynamicValue {
                            msgpack: vec![],
                            json,
                        }),
                        prior_private: vec![],
                        provider_meta: None,
                        client_capabilities: None,
                        prior_identity: None,
                    })
                    .await
                    .map_err(|s| ProviderError::Rpc {
                        rpc: "plan_resource_change",
                        status: s.to_string(),
                    })?
                    .into_inner();
                check_v5_diags("plan_resource_change", &resp.diagnostics)?;
                let planned = resp.planned_state.ok_or(ProviderError::EmptyResponse {
                    rpc: "plan_resource_change",
                    what: "planned_state",
                })?;
                Ok(PlannedCreate {
                    planned_state_msgpack: planned.msgpack,
                    planned_state_json: planned.json,
                    planned_private: resp.planned_private,
                })
            }
            other => Err(ProviderError::UnsupportedProtocol(other)),
        }
    }

    /// `ApplyResourceChange` for a create. Returns the new resource state
    /// decoded into a `serde_json::Value` (ready to drop into
    /// `StateInstance.attributes`).
    pub async fn apply_create(
        &self,
        type_name: &str,
        planned: &PlannedCreate,
        config: &Value,
    ) -> Result<Value, ProviderError> {
        let json = to_json_bytes(config)?;
        match self.protocol {
            PluginProtocol::V5 => {
                let mut c = self.v5();
                let resp = c
                    .apply_resource_change(tfplugin5::apply_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(null_dynamic_value_v5()),
                        planned_state: Some(tfplugin5::DynamicValue {
                            msgpack: planned.planned_state_msgpack.clone(),
                            json: planned.planned_state_json.clone(),
                        }),
                        config: Some(tfplugin5::DynamicValue {
                            msgpack: vec![],
                            json,
                        }),
                        planned_private: planned.planned_private.clone(),
                        provider_meta: None,
                        planned_identity: None,
                    })
                    .await
                    .map_err(|s| ProviderError::Rpc {
                        rpc: "apply_resource_change",
                        status: s.to_string(),
                    })?
                    .into_inner();
                check_v5_diags("apply_resource_change", &resp.diagnostics)?;
                let new_state = resp.new_state.ok_or(ProviderError::EmptyResponse {
                    rpc: "apply_resource_change",
                    what: "new_state",
                })?;
                // Provider responds in msgpack; json is usually empty.
                if !new_state.msgpack.is_empty() {
                    decode_dynamic_value_msgpack(&new_state.msgpack)
                } else if !new_state.json.is_empty() {
                    serde_json::from_slice(&new_state.json)
                        .map_err(|e| ProviderError::Decode(e.to_string()))
                } else {
                    Err(ProviderError::EmptyResponse {
                        rpc: "apply_resource_change",
                        what: "new_state payload",
                    })
                }
            }
            other => Err(ProviderError::UnsupportedProtocol(other)),
        }
    }

    fn v5(&self) -> tfplugin5::provider_client::ProviderClient<Channel> {
        tfplugin5::provider_client::ProviderClient::new(self.channel.clone())
    }
}

// ── helpers ────────────────────────────────────────────────────────

fn to_json_bytes(v: &Value) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(v).map_err(|e| ProviderError::Encode(e.to_string()))
}

fn null_dynamic_value_v5() -> tfplugin5::DynamicValue {
    tfplugin5::DynamicValue {
        msgpack: vec![],
        json: b"null".to_vec(),
    }
}

fn check_v5_diags(
    rpc: &'static str,
    diags: &[tfplugin5::Diagnostic],
) -> Result<(), ProviderError> {
    let errors: Vec<String> = diags
        .iter()
        .filter(|d| d.severity == tfplugin5::diagnostic::Severity::Error as i32)
        .map(|d| {
            if d.detail.is_empty() {
                d.summary.clone()
            } else {
                format!("{}: {}", d.summary, d.detail)
            }
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ProviderError::Diagnostics {
            rpc,
            diags: errors.join("; "),
        })
    }
}

/// terraform's `os_arch` directory name (e.g. `darwin_arm64`,
/// `linux_amd64`) for the current host.
fn current_os_arch() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    };
    format!("{os}_{arch}")
}

/// Immediate subdirectories of `dir` (empty if unreadable).
fn read_subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

/// Find a `terraform-provider-<name>*` executable in `dir`.
fn find_provider_binary(dir: &Path, name: &str) -> Option<PathBuf> {
    let prefix = format!("terraform-provider-{name}");
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            return Some(e.path());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_is_null() {
        assert_eq!(decode_dynamic_value_msgpack(&[]).unwrap(), Value::Null);
    }

    #[test]
    fn decode_msgpack_map_roundtrips() {
        let original = serde_json::json!({
            "id": "r-1",
            "triggers": { "k": "v" },
            "n": 3,
        });
        let rv: rmpv::Value = rmpv::ext::to_value(&original).unwrap();
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rv).unwrap();
        let decoded = decode_dynamic_value_msgpack(&buf).unwrap();
        assert_eq!(decoded["id"], serde_json::json!("r-1"));
        assert_eq!(decoded["triggers"]["k"], serde_json::json!("v"));
        assert_eq!(decoded["n"], serde_json::json!(3));
    }

    #[test]
    fn os_arch_is_nonempty() {
        let oa = current_os_arch();
        assert!(oa.contains('_'), "os_arch malformed: {oa}");
    }

    #[test]
    fn resolve_missing_errors_loudly() {
        let reg = ProviderRegistry::new("/nonexistent-plugin-cache-xyz");
        let err = reg.resolve("integrations/github").unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }
}
