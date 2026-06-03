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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use chrono::Utc;
use magma_config::resolve_reference;
use magma_cty::DynamicValue;
use magma_graph::ResourceGraph;
use magma_plugin::provider::{ProviderConn, ProviderSchema, is_retryable};
use magma_plugin::{Plugin, PluginSpec};
use magma_types::{
    Action, Plan, ResourceAddress, ResourceChange, State, StateInstance, StateResource,
};

use crate::{AppliedChange, ApplyOutcome, FailedChange, insert_resource, remove_resource};

/// Retry an async provider RPC with exponential backoff on transient errors
/// (chiefly provider-side rate limiting — see [`is_retryable`]). Re-evaluates
/// the call expression each attempt (so it re-borrows the connection cleanly).
/// Permanent errors fail fast; transient ones back off up to ~45s, 7 attempts.
macro_rules! rpc_retry {
    ($call:expr) => {{
        let mut delay = std::time::Duration::from_millis(800);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match $call.await {
                Ok(v) => break Ok(v),
                Err(e) if attempt < 7 && is_retryable(&e) => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        delay_ms = delay.as_millis() as u64,
                        "magma: retryable provider error — backing off"
                    );
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(
                        delay.saturating_mul(2),
                        std::time::Duration::from_secs(45),
                    );
                }
                Err(e) => break Err(e),
            }
        }
    }};
}

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

    let mkfail = |c: &ResourceChange, e: EngineError| FailedChange {
        address: c.address.clone(),
        action: c.action,
        reason: e.to_string(),
    };

    // Resolution map (type → {name → attributes}), the basis for substituting
    // ${type.name.attr} references at apply time. Seed it from existing state
    // so references to already-extant (matched) resources resolve immediately;
    // it grows as each real change is applied.
    let mut state_map: HashMap<String, serde_json::Value> = HashMap::new();
    for r in &state.resources {
        if let Some(inst) = r.instances.first() {
            sm_insert(&mut state_map, &r.address, &inst.attributes);
        }
    }

    // NoOp (matched) changes pass through with no provider call and no
    // ordering; real changes (Create/Update/Delete/…) get dependency-ordered
    // + reference-substituted apply below.
    let (noops, reals): (Vec<&ResourceChange>, Vec<&ResourceChange>) = plan
        .resource_changes
        .iter()
        .partition(|c| c.action == Action::NoOp);

    for change in noops {
        match apply_one(change, state, &mut registry).await {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(mkfail(change, e)),
        }
    }

    // Build the dependency graph from ${type.name.attr} references that point
    // at OTHER real changes, so each resource is applied before anything that
    // consumes its computed attributes (node_id, id, …).
    let real_keys: HashSet<(String, String)> = reals
        .iter()
        .map(|c| (c.address.type_id.0.clone(), c.address.name.clone()))
        .collect();
    let by_key: HashMap<(String, String), &ResourceChange> = reals
        .iter()
        .map(|c| ((c.address.type_id.0.clone(), c.address.name.clone()), *c))
        .collect();

    let mut graph = ResourceGraph::new();
    for c in &reals {
        graph.add(c.address.clone());
    }
    for c in &reals {
        let self_key = (c.address.type_id.0.clone(), c.address.name.clone());
        if let Some(after) = &c.after {
            for refstr in collect_refs(after) {
                if let Some(dep_key) = ref_target(&refstr) {
                    if dep_key != self_key && real_keys.contains(&dep_key) {
                        if let Some(dep) = by_key.get(&dep_key) {
                            graph.depend(c.address.clone(), dep.address.clone());
                        }
                    }
                }
            }
        }
    }

    // Flattened topological waves. On a cycle / graph error, fall back to plan
    // order — attempt the apply rather than refuse the whole cycle.
    let ordered: Vec<ResourceAddress> = match graph.waves() {
        Ok(waves) => waves.into_iter().flatten().collect(),
        Err(e) => {
            tracing::warn!(error = %e, "magma: dependency-graph error — applying in plan order");
            reals.iter().map(|c| c.address.clone()).collect()
        }
    };

    for addr in ordered {
        let key = (addr.type_id.0.clone(), addr.name.clone());
        let Some(change) = by_key.get(&key).copied() else {
            continue;
        };
        // Substitute ${ref}s against everything applied so far.
        let mut resolved = change.clone();
        if let Some(after) = resolved.after.as_mut() {
            substitute_refs(after, &state_map);
        }
        match apply_one(&resolved, state, &mut registry).await {
            Ok(a) => {
                if let Some(attrs) = &a.after {
                    // Provider-returned new_state feeds dependents' references.
                    sm_insert(&mut state_map, &change.address, attrs);
                }
                applied.push(a);
            }
            Err(e) => failed.push(mkfail(change, e)),
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
            match rpc_retry!(lp.conn.read_resource(&type_name, &prior_dv)) {
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
            rpc_retry!(lp
                .conn
                .apply_resource_change(&type_name, &prior_dv, &null_dv, &null_dv))
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
            let planned_dv = rpc_retry!(lp.conn.plan_resource_change(
                &type_name,
                &prior_dv,
                &config_dv,
                &config_dv
            ))
            .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?;
            let new_dv = rpc_retry!(lp.conn.apply_resource_change(
                &type_name,
                &prior_dv,
                &planned_dv,
                &config_dv
            ))
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

// ── Apply-time reference resolution helpers ───────────────────────────────
//
// References in a rendered config are literal `${type.name.attr}` strings in
// the JSON (magma-plan leaves them untouched). The apply engine resolves them
// against a `state_map` (type → {name → attributes}) as resources are
// created — the substitution `resolve_reference` consumes is shaped exactly
// like the map navigation it does (head = type, then name, then attr path).

/// Insert/overwrite a resource's attributes into the resolution map under
/// `type → name`.
fn sm_insert(
    sm: &mut HashMap<String, serde_json::Value>,
    addr: &ResourceAddress,
    attrs: &serde_json::Value,
) {
    let entry = sm
        .entry(addr.type_id.0.clone())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let serde_json::Value::Object(map) = entry {
        map.insert(addr.name.clone(), attrs.clone());
    }
}

/// Collect every `${…}` reference path (inner, no wrapper) found anywhere in
/// a config value.
fn collect_refs(v: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => {
                let mut rest = s.as_str();
                while let Some(start) = rest.find("${") {
                    let after = &rest[start + 2..];
                    if let Some(end) = after.find('}') {
                        out.push(after[..end].trim().to_string());
                        rest = &after[end + 1..];
                    } else {
                        break;
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// The `(type, name)` a reference path targets — `github_repository.galho.node_id`
/// → `("github_repository", "galho")`. Returns `None` for `data.*` sources
/// (resolved from existing state, not ordered as apply dependencies) or
/// malformed paths. Strips any `[index]` from the name segment.
fn ref_target(inner: &str) -> Option<(String, String)> {
    let segs: Vec<&str> = inner.split('.').collect();
    if segs.first() == Some(&"data") {
        return None;
    }
    if segs.len() >= 2 {
        let name = segs[1].split('[').next().unwrap_or(segs[1]);
        return Some((segs[0].to_string(), name.to_string()));
    }
    None
}

/// Replace `${type.name.attr}` references in-place against `sm`. A value that
/// is exactly one reference is replaced by the resolved value (preserving its
/// type); an interpolated string has each `${…}` substituted with the
/// resolved value stringified. Unresolvable references are left untouched
/// (the apply may then fail, surfacing the gap rather than masking it).
fn substitute_refs(v: &mut serde_json::Value, sm: &HashMap<String, serde_json::Value>) {
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if let Some(inner) = trimmed.strip_prefix("${").and_then(|x| x.strip_suffix('}')) {
                if !inner.contains("${") {
                    if let Ok(resolved) = resolve_reference(trimmed, sm) {
                        *v = resolved;
                    }
                    return;
                }
            }
            if s.contains("${") {
                let mut result = String::new();
                let mut rest = s.as_str();
                while let Some(start) = rest.find("${") {
                    result.push_str(&rest[..start]);
                    let after = &rest[start + 2..];
                    if let Some(end) = after.find('}') {
                        let full = &rest[start..start + 2 + end + 1];
                        match resolve_reference(full, sm) {
                            Ok(serde_json::Value::String(rs)) => result.push_str(&rs),
                            Ok(other) => result.push_str(&other.to_string()),
                            Err(_) => result.push_str(full),
                        }
                        rest = &after[end + 1..];
                    } else {
                        result.push_str(&rest[start..]);
                        rest = "";
                        break;
                    }
                }
                result.push_str(rest);
                *s = result;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| substitute_refs(x, sm)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| substitute_refs(x, sm)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_time_reference_resolution() {
        use serde_json::json;
        // state_map shaped like resolve_reference navigates: type → {name → attrs}.
        // github_repository.galho has just been "applied" with a computed node_id.
        let mut sm: HashMap<String, serde_json::Value> = HashMap::new();
        sm.insert(
            "github_repository".into(),
            json!({ "galho": { "node_id": "R_kgABCDEF", "name": "galho" } }),
        );

        // collect_refs finds the dependency.
        let after = json!({
            "repository_id": "${github_repository.galho.node_id}",
            "pattern": "main",
            "msg": "repo ${github_repository.galho.name} protected",
        });
        let refs = collect_refs(&after);
        assert!(refs.contains(&"github_repository.galho.node_id".to_string()));

        // ref_target maps a path to its (type, name) dependency.
        assert_eq!(
            ref_target("github_repository.galho.node_id"),
            Some(("github_repository".into(), "galho".into()))
        );
        assert_eq!(ref_target("data.github_repository.x.id"), None);

        // substitute_refs resolves a PURE ref (type preserved) + an
        // INTERPOLATED ref (stringified into the surrounding text).
        let mut resolved = after;
        substitute_refs(&mut resolved, &sm);
        assert_eq!(resolved["repository_id"], json!("R_kgABCDEF"));
        assert_eq!(resolved["pattern"], json!("main"));
        assert_eq!(resolved["msg"], json!("repo galho protected"));

        // An unresolvable ref is left untouched (surfaces, not masked).
        let mut dangling = json!({ "x": "${github_repository.ghost.id}" });
        substitute_refs(&mut dangling, &sm);
        assert_eq!(dangling["x"], json!("${github_repository.ghost.id}"));
    }

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

    /// The load-bearing safety invariant: refresh must NEVER drop state when
    /// it cannot read the resource. Here no provider is locatable (empty
    /// workspace, no `$MAGMA_PROVIDER_DIR`), so every instance is kept
    /// unchanged and counted as `kept_on_error` — a transient provider/RPC
    /// failure can never silently delete real state.
    #[tokio::test]
    async fn refresh_never_drops_when_provider_unavailable() {
        use magma_types::{
            InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind,
            ResourceTypeId, StateInstance, StateResource,
        };
        // Ensure no baked mirror leaks in from the test env.
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };

        let mut state = State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![StateResource {
                address: ResourceAddress {
                    module: ModulePath::root(),
                    kind: ResourceKind::Managed,
                    type_id: ResourceTypeId("github_repository".into()),
                    name: "keep_me".into(),
                    key: None,
                },
                provider: ProviderReference {
                    source: "integrations/github".into(),
                    name: "github".into(),
                    alias: None,
                },
                instances: vec![StateInstance {
                    schema_version: 0,
                    attributes: serde_json::json!({"name": "keep_me"}),
                    private: vec![],
                    dependencies: vec![],
                    status: InstanceStatus::Ready,
                }],
            }],
        };

        let td = tempfile::tempdir().unwrap();
        let ctx = ApplyContext::new(td.path().to_path_buf());
        let report = refresh_state(&mut state, &ctx).await;

        assert_eq!(report.dropped_instances, 0, "must not drop on read failure");
        assert_eq!(report.dropped_resources, 0);
        assert_eq!(report.kept_on_error, 1, "kept the instance it couldn't read");
        assert_eq!(state.resources.len(), 1, "resource survives uncertainty");
    }
}
