//! Provider-backed apply engine — the **real** `run_plan`.
//!
//! [`run_plan_with_providers`] is the executor that makes magma actually
//! create / update / delete infrastructure instead of only mutating
//! state ([`crate::run_plan`] is the structural M0 path). For every plan
//! change it spawns the provider (once, cached + configured), runs
//! `PlanResourceChange` → `ApplyResourceChange` over tfplugin6, and folds
//! the provider's returned state back into magma [`State`]. No subprocess
//! to tofu — magma drives the provider plugin directly.
//!
//! The pieces compose the lower layers: [`magma_providers`] locates the
//! binary, [`magma_plugin::Plugin`] spawns + mTLS-dials it,
//! [`magma_plugin::provider::ProviderConn`] speaks the RPCs, and
//! [`magma_cty`] encodes attributes against the schema-derived type.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use chrono::Utc;
use magma_cty::DynamicValue;
use magma_plugin::provider::{ProviderConn, ProviderSchema};
use magma_plugin::{Plugin, PluginSpec};
use magma_types::{Action, Plan, ResourceChange, State, StateInstance, StateResource};

use crate::{AppliedChange, ApplyOutcome, FailedChange, insert_resource, remove_resource};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("locate provider {0:?}: {1}")]
    Locate(String, String),
    #[error("spawn provider {0:?}: {1}")]
    Spawn(String, String),
    #[error("provider {0:?} RPC: {1}")]
    Rpc(String, String),
    #[error("provider {1:?} has no schema for resource type {0:?}")]
    NoResourceSchema(String, String),
    #[error("cty encode/decode: {0}")]
    Cty(String),
}

/// What the apply needs beyond `(plan, state)`: where the provider
/// binaries live (the workspace's `.terraform/providers`, populated by
/// `init`) and each provider's configuration (credentials).
pub struct ApplyContext {
    pub workspace_dir: PathBuf,
    pub terraform_version: String,
    /// provider local name (e.g. `"github"`) → `ConfigureProvider` config
    /// as JSON (e.g. `{ "token": "…", "owner": "pleme-io" }`).
    pub provider_configs: BTreeMap<String, serde_json::Value>,
}

impl ApplyContext {
    pub fn new(workspace_dir: PathBuf) -> Self {
        Self {
            workspace_dir,
            terraform_version: "1.9.0".to_string(),
            provider_configs: BTreeMap::new(),
        }
    }

    pub fn with_provider_config(
        mut self,
        name: impl Into<String>,
        config: serde_json::Value,
    ) -> Self {
        self.provider_configs.insert(name.into(), config);
        self
    }
}

/// A spawned + configured provider held for the apply's lifetime (so
/// each provider spawns + configures exactly once). `Plugin`'s `Drop`
/// terminates the subprocess.
struct LiveProvider {
    _plugin: Plugin,
    conn: ProviderConn,
    schema: ProviderSchema,
}

struct Registry<'a> {
    ctx: &'a ApplyContext,
    live: HashMap<String, LiveProvider>,
}

impl<'a> Registry<'a> {
    fn new(ctx: &'a ApplyContext) -> Self {
        Self {
            ctx,
            live: HashMap::new(),
        }
    }

    async fn get(&mut self, name: &str) -> Result<&mut LiveProvider, EngineError> {
        if !self.live.contains_key(name) {
            let lp = self.spawn(name).await?;
            self.live.insert(name.to_string(), lp);
        }
        Ok(self.live.get_mut(name).expect("just inserted"))
    }

    async fn spawn(&self, name: &str) -> Result<LiveProvider, EngineError> {
        let binary = magma_providers::locate_provider(&self.ctx.workspace_dir, name)
            .map_err(|e| EngineError::Locate(name.into(), e.to_string()))?;
        let mut plugin = Plugin::spawn(PluginSpec {
            binary,
            // mTLS (go-plugin AutoMTLS) — real providers (github/SDKv2)
            // serve TLS even without a client cert, so plaintext h2c isn't
            // an option. `secure=false` remains available for providers
            // that do serve plaintext.
            secure: true,
            ..Default::default()
        })
        .await
        .map_err(|e| EngineError::Spawn(name.into(), e.to_string()))?;
        // The handshake's negotiated protocol selects the tfplugin5/6
        // client (SDKv2 providers like github speak v5; framework v6).
        let protocol = plugin.handshake().app_protocol;
        let channel = plugin
            .dial()
            .await
            .map_err(|e| EngineError::Spawn(name.into(), e.to_string()))?
            .clone();
        let mut conn = ProviderConn::new(channel, protocol);
        let schema = conn
            .get_schema()
            .await
            .map_err(|e| EngineError::Rpc(name.into(), e.to_string()))?;

        // Configure: the provider-config-typed creds, or an empty object
        // (→ a provider-config object with all attributes null, which is
        // what terraform sends for an absent provider block; the provider
        // falls back to its own env credentials). NOT a null object —
        // providers expect a value of the config type, not nil.
        let config_json = self
            .ctx
            .provider_configs
            .get(name)
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        let config_dv = DynamicValue::from_json(&config_json, &schema.provider_config)
            .map_err(|e| EngineError::Cty(e.to_string()))?;
        conn.configure(&config_dv, &self.ctx.terraform_version)
            .await
            .map_err(|e| EngineError::Rpc(name.into(), e.to_string()))?;

        Ok(LiveProvider {
            _plugin: plugin,
            conn,
            schema,
        })
    }
}

/// Apply a plan against `state` by driving the real providers. Mirrors
/// [`crate::run_plan`]'s outcome shape so the operator's `MagmaExecutor`
/// can swap one for the other.
pub async fn run_plan_with_providers(
    plan: &Plan,
    state: &mut State,
    ctx: &ApplyContext,
) -> ApplyOutcome {
    let started_at = Utc::now();
    let mut registry = Registry::new(ctx);
    let mut applied = Vec::new();
    let mut failed = Vec::new();

    for change in &plan.resource_changes {
        match apply_one(change, state, &mut registry).await {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(FailedChange {
                address: change.address.clone(),
                action: change.action,
                reason: e.to_string(),
            }),
        }
    }

    if !applied.is_empty() {
        state.serial = state.serial.saturating_add(1);
    }

    ApplyOutcome {
        plan_id: plan.id,
        state: state.clone(),
        applied,
        failed,
        started_at,
        finished_at: Utc::now(),
    }
}

/// What a [`refresh_state`] pass did, for logging + receipts.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefreshReport {
    /// Instances whose attributes were updated from the provider.
    pub refreshed: usize,
    /// Instances the provider reported gone (dropped from state).
    pub dropped_instances: usize,
    /// Resources dropped entirely (all their instances were gone).
    pub dropped_resources: usize,
    /// Instances kept unchanged because refresh couldn't be performed
    /// (provider spawn failure, missing schema, encode/decode error, RPC
    /// error). Refresh NEVER drops state on uncertainty — only on a
    /// confirmed null `ReadResource`.
    pub kept_on_error: usize,
}

/// Refresh `state` against the providers' ACTUAL current state — terraform's
/// plan-time refresh. For every resource instance, call `ReadResource`:
///
/// * provider reports it **gone** (cty-null) → drop the instance. This
///   self-heals phantom entries — e.g. a resource a prior structural-only
///   apply recorded in state but never actually created — so the next plan
///   re-creates it.
/// * provider returns refreshed state → update the instance's attributes
///   (so drift in real attributes is detected).
/// * any error / uncertainty → KEEP the instance unchanged. Refresh must
///   never delete state because a read failed.
///
/// Resources whose every instance went away are removed entirely. Returns a
/// [`RefreshReport`] for the caller's cycle receipt.
pub async fn refresh_state(state: &mut State, ctx: &ApplyContext) -> RefreshReport {
    let mut registry = Registry::new(ctx);
    let mut report = RefreshReport::default();
    let mut kept: Vec<StateResource> = Vec::new();

    for resource in std::mem::take(&mut state.resources) {
        let type_name = resource.address.type_id.0.clone();
        let provider_name = provider_local_name(&type_name);

        // Resolve the implied type once (clone so the schema borrow ends
        // before the per-instance mutable RPC borrows). Any failure here ⇒
        // keep the whole resource untouched.
        let implied = match registry.get(&provider_name).await {
            Ok(lp) => match lp.schema.resource(&type_name) {
                Some(t) => t.clone(),
                None => {
                    report.kept_on_error += resource.instances.len();
                    kept.push(resource);
                    continue;
                }
            },
            Err(_) => {
                report.kept_on_error += resource.instances.len();
                kept.push(resource);
                continue;
            }
        };

        let mut kept_instances: Vec<StateInstance> = Vec::new();
        for inst in resource.instances {
            let prior_dv = match DynamicValue::from_json(&inst.attributes, &implied) {
                Ok(d) => d,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            let lp = match registry.get(&provider_name).await {
                Ok(l) => l,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            match lp.conn.read_resource(&type_name, &prior_dv).await {
                Ok(None) => {
                    // Confirmed gone — drop this phantom/deleted instance.
                    report.dropped_instances += 1;
                }
                Ok(Some(dv)) => match dv.to_json(&implied) {
                    Ok(attrs) => {
                        report.refreshed += 1;
                        kept_instances.push(StateInstance {
                            attributes: attrs,
                            ..inst
                        });
                    }
                    Err(_) => {
                        report.kept_on_error += 1;
                        kept_instances.push(inst);
                    }
                },
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                }
            }
        }

        if kept_instances.is_empty() {
            report.dropped_resources += 1;
        } else {
            kept.push(StateResource {
                instances: kept_instances,
                ..resource
            });
        }
    }

    state.resources = kept;
    report
}

async fn apply_one(
    change: &ResourceChange,
    state: &mut State,
    reg: &mut Registry<'_>,
) -> Result<AppliedChange, EngineError> {
    if change.action == Action::NoOp {
        return Ok(AppliedChange {
            address: change.address.clone(),
            action: Action::NoOp,
            before: change.before.clone(),
            after: change.after.clone(),
        });
    }

    let type_name = change.address.type_id.0.clone();
    let provider_name = provider_local_name(&type_name);
    let lp = reg.get(&provider_name).await?;
    // Clone the implied type so the immutable schema borrow ends before
    // the mutable conn RPC calls.
    let implied = lp
        .schema
        .resource(&type_name)
        .ok_or_else(|| EngineError::NoResourceSchema(type_name.clone(), provider_name.clone()))?
        .clone();

    let null_json = serde_json::Value::Null;
    let prior_dv = DynamicValue::from_json(change.before.as_ref().unwrap_or(&null_json), &implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;

    match change.action {
        Action::Delete | Action::Forget => {
            let null_dv = DynamicValue::from_json(&null_json, &implied)
                .map_err(|e| EngineError::Cty(e.to_string()))?;
            lp.conn
                .apply_resource_change(&type_name, &prior_dv, &null_dv, &null_dv)
                .await
                .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?;
            remove_resource(state, &change.address);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: None,
            })
        }
        // Create / Update / Replace / CreateThenDelete / DeleteThenCreate / Read
        _ => {
            let config_json = change.after.clone().unwrap_or(serde_json::Value::Null);
            let config_dv = DynamicValue::from_json(&config_json, &implied)
                .map_err(|e| EngineError::Cty(e.to_string()))?;
            // Provider normalizes the proposed state (computes defaults +
            // marks computed attributes unknown). Terraform requires the
            // planned state to flow from plan → apply.
            let planned_dv = lp
                .conn
                .plan_resource_change(&type_name, &prior_dv, &config_dv, &config_dv)
                .await
                .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?;
            let new_dv = lp
                .conn
                .apply_resource_change(&type_name, &prior_dv, &planned_dv, &config_dv)
                .await
                .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?;
            let new_attrs = new_dv
                .to_json(&implied)
                .map_err(|e| EngineError::Cty(e.to_string()))?;
            insert_resource(state, &change.address, new_attrs.clone());
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: Some(new_attrs),
            })
        }
    }
}

/// The provider's local name from a resource type id: the prefix before
/// the first `_` (`github_repository` → `github`, `aws_s3_bucket` →
/// `aws`). Matches `terraform-provider-<name>`.
fn provider_local_name(type_id: &str) -> String {
    type_id.split('_').next().unwrap_or(type_id).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_local_name_extracts_prefix() {
        assert_eq!(provider_local_name("github_repository"), "github");
        assert_eq!(provider_local_name("aws_s3_bucket"), "aws");
        assert_eq!(provider_local_name("cloudflare_record"), "cloudflare");
        assert_eq!(provider_local_name("noprefix"), "noprefix");
    }

    #[test]
    fn apply_context_builder() {
        let ctx = ApplyContext::new(PathBuf::from("/ws"))
            .with_provider_config("github", serde_json::json!({"owner": "pleme-io"}));
        assert_eq!(ctx.workspace_dir, PathBuf::from("/ws"));
        assert!(ctx.provider_configs.contains_key("github"));
    }
}
