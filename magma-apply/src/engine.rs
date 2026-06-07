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
use std::sync::Arc;

use chrono::Utc;
use magma_config::resolve_reference;
use samba::LeakyBucket;
use magma_cty::DynamicValue;
use magma_graph::ResourceGraph;
use magma_plugin::provider::{ProviderConn, ProviderSchema, is_retryable};
use magma_plugin::{Plugin, PluginSpec};
use magma_types::{
    Action, Plan, ResourceAddress, ResourceChange, ResourceKind, State, StateInstance,
    StateResource,
};

use crate::{AppliedChange, ApplyOutcome, FailedChange, insert_resource, remove_resource};

/// Retry an async provider RPC with exponential backoff on transient errors
/// (chiefly provider-side rate limiting — see [`is_retryable`]). Re-evaluates
/// the call expression each attempt (so it re-borrows the connection cleanly).
/// Permanent errors fail fast; transient ones back off up to ~45s, 7 attempts.
macro_rules! rpc_retry {
    ($pacer:expr, $call:expr) => {{
        let mut delay = std::time::Duration::from_millis(800);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match $call.await {
                Ok(v) => break Ok(v),
                Err(e) if attempt < 7 && is_retryable(&e) => {
                    // A retryable provider error is almost always a secondary
                    // rate limit. Beyond backing off this call, escalate the
                    // shared pacer to maximum back-pressure (samba Emergency,
                    // 0.125× pace) so EVERY subsequent mutation this cycle is
                    // spaced way out — synthesized 0% headroom drives the
                    // level (magma can't read the provider's X-RateLimit
                    // headers, so error-occurrence is the pressure signal).
                    if let Some(p) = $pacer {
                        p.record_headroom(0, 100).await;
                    }
                    tracing::warn!(
                        attempt,
                        error = %e,
                        delay_ms = delay.as_millis() as u64,
                        "magma: retryable provider error — backing off + raising pace pressure"
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
    /// Strict-pace governor for provider MUTATION RPCs (samba `LeakyBucket`).
    /// `apply_one` acquires one token before each non-NoOp resource's RPCs so
    /// a bulk apply (e.g. 50 GitHub creates) can't burst past the provider's
    /// secondary rate limit. `None` = unpaced. NoOps never acquire.
    pub pacer: Option<Arc<LeakyBucket>>,
}

/// Default mutation pace: 1 request/second — GitHub's documented minimum
/// spacing between mutative API requests, and a safe floor for any provider.
/// `quota_pct = 1.0 × 3600 rph / 60 = 60 rpm`; `burst = 1` means strict
/// spacing (no bursts — bursts are exactly what trips secondary limits);
/// 10% jitter de-synchronizes retried calls.
const DEFAULT_PACE_RPH: f64 = 3600.0;

fn build_pacer(rph: f64) -> Option<Arc<LeakyBucket>> {
    if rph <= 0.0 {
        return None;
    }
    match LeakyBucket::new(1.0, rph, 50, 25, 0.1, 1) {
        Ok(b) => Some(Arc::new(b)),
        Err(e) => {
            tracing::warn!(error = %e, "magma: failed to build apply pacer — proceeding unpaced");
            None
        }
    }
}

impl ApplyContext {
    pub fn new(workspace_dir: PathBuf) -> Self {
        Self {
            workspace_dir,
            terraform_version: "1.9.0".to_string(),
            provider_configs: BTreeMap::new(),
            pacer: build_pacer(DEFAULT_PACE_RPH),
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

    /// Override the mutation pace (full-pressure requests/hour). `<= 0`
    /// disables pacing entirely.
    #[must_use]
    pub fn with_pace_rph(mut self, rph: f64) -> Self {
        self.pacer = build_pacer(rph);
        self
    }

    /// Disable RPC pacing (e.g. tests, or a provider with no rate limit).
    #[must_use]
    pub fn without_pacer(mut self) -> Self {
        self.pacer = None;
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

    let mkfail = |c: &ResourceChange, e: EngineError| {
        // Observability: surface EVERY failed change with its address +
        // action + provider reason. Previously the apply collapsed failures
        // into a bare count, so the per-resource cause was invisible in the
        // operator log (had to be archaeologated from the on-disk bundle).
        tracing::warn!(
            address = ?c.address,
            action = ?c.action,
            reason = %e,
            "magma apply: change failed"
        );
        FailedChange {
            address: c.address.clone(),
            action: c.action,
            reason: e.to_string(),
        }
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
    let (noops, rest): (Vec<&ResourceChange>, Vec<&ResourceChange>) = plan
        .resource_changes
        .iter()
        .partition(|c| c.action == Action::NoOp);
    // Data sources are evaluated up front (ReadDataSource) so their results
    // populate the resolution map under `data.<type>.<name>` BEFORE any managed
    // resource that references them is applied. Without this the `${data.*}`
    // strings leaked verbatim into the provider RPC (the rio-drive 400).
    let (datas, reals): (Vec<&ResourceChange>, Vec<&ResourceChange>) = rest
        .into_iter()
        .partition(|c| c.address.kind == ResourceKind::Data);

    for change in noops {
        match apply_one(change, state, &mut registry).await {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(mkfail(change, e)),
        }
    }

    // Read each data source + fold its result into state_map under the `data`
    // head, so `${data.<type>.<name>.<attr>}` references resolve in the managed
    // pass below. (Data sources are not graph-ordered — they have no computed
    // deps on managed resources; ref_target deliberately returns None for them.)
    for change in &datas {
        // Resolve any refs in the data-source config first (usually literal).
        let mut resolved = (*change).clone();
        if let Some(after) = resolved.after.as_mut() {
            substitute_refs(after, &state_map);
        }
        match read_data_source_one(&resolved, &mut registry).await {
            Ok(result) => {
                sm_insert_data(&mut state_map, &change.address, &result);
                applied.push(AppliedChange {
                    address: change.address.clone(),
                    action: change.action,
                    before: None,
                    after: Some(result),
                });
            }
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

    // Self-heal phantom parents: a child create that failed with a
    // `404 .../repos/<owner>/<repo>/...` — or an unresolved
    // `${github_repository.<name>....}` reference — means the parent repo is a
    // PHANTOM (recorded in state but absent in cloud), so the plan NoOp'd it
    // and never created it. Drop it from state here; the next plan re-creates
    // it and its children then resolve. This reacts to the REAL apply failure,
    // so it converges independently of ReadResource null-vs-404 semantics and
    // of any plan-time refresh suspect-matching.
    let phantoms = collect_phantom_parents(&failed);
    let dropped_phantoms = if phantoms.is_empty() {
        0
    } else {
        drop_repos_from_state(state, &phantoms)
    };
    if dropped_phantoms > 0 {
        tracing::warn!(
            phantom_parents = phantoms.len(),
            dropped = dropped_phantoms,
            "magma apply: dropped phantom parent repos (children 404'd — in state, gone in cloud); re-creating next cycle"
        );
    }

    if !applied.is_empty() || dropped_phantoms > 0 {
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

/// Parse the parent `github_repository` identifiers that a set of failed
/// changes implicate as PHANTOMS: a `404 .../repos/<owner>/<repo>/...` (the
/// repo NAME) or an unresolved `${github_repository.<name>....}` (the resource
/// NAME) in the failure reason. Both forms are collected so
/// [`drop_repos_from_state`] can match either the state resource-name or its
/// `attributes["name"]`. Only repo-scoped 404 paths match — a repo-create's
/// own `404 /orgs/.../repos` (already-exists) or an org-block path never do,
/// so inverse-phantoms aren't wrongly dropped.
fn collect_phantom_parents(failed: &[FailedChange]) -> HashSet<String> {
    let mut out = HashSet::new();
    for f in failed {
        let r = f.reason.as_str();
        // `.../repos/<owner>/<repo>/<child>...` → repo NAME (a child 404'd on
        // a repo that doesn't exist). Require the 3rd `/`-segment (a child
        // path) so a bare `/repos/owner/repo` or an `/orgs/.../repos`
        // create-404 isn't mistaken for a parent.
        let mut rest = r;
        while let Some(i) = rest.find("/repos/") {
            let after = &rest[i + "/repos/".len()..];
            let parts: Vec<&str> = after.splitn(3, '/').collect();
            if parts.len() == 3 {
                let repo = parts[1].trim();
                if !repo.is_empty() {
                    out.insert(repo.to_string());
                }
            }
            rest = after;
        }
        // unresolved `${github_repository.<name>.<attr>}` → resource NAME.
        let mut rest2 = r;
        while let Some(i) = rest2.find("${github_repository.") {
            let after = &rest2[i + "${github_repository.".len()..];
            let name: String = after.chars().take_while(|c| *c != '.' && *c != '}').collect();
            if !name.is_empty() {
                out.insert(name);
            }
            rest2 = after;
        }
    }
    out
}

/// Drop every `github_repository` resource from `state` whose resource-name OR
/// `attributes["name"]` is in `names`. Returns the count of resources removed.
/// Evicts phantoms so the next plan re-creates them.
fn drop_repos_from_state(state: &mut State, names: &HashSet<String>) -> usize {
    let before = state.resources.len();
    state.resources.retain(|r| {
        if r.address.type_id.0 != "github_repository" {
            return true;
        }
        let by_addr = names.contains(&r.address.name);
        let by_attr = r
            .instances
            .first()
            .and_then(|i| i.attributes.get("name"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|n| names.contains(n));
        !(by_addr || by_attr)
    });
    before - state.resources.len()
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
    /// Whole-resource drops that the mass-drop safety guard SUPPRESSED and
    /// restored (see [`refresh_named`]). Non-zero ⇒ a systemic read
    /// malfunction was detected (a large fraction of probed targets all read
    /// "gone" at once) and the drop was refused to protect state from the
    /// false-drop → +N-create → adopt oscillation. `dropped_*` are zeroed when
    /// this fires.
    pub suppressed_mass_drop: usize,
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
            match rpc_retry!(None::<&LeakyBucket>, lp.conn.read_resource(&type_name, &prior_dv)) {
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

/// From a plan's CREATE changes, collect the names of the parent
/// `github_repository` resources they depend on — both the literal
/// `repository` field value (the repo NAME, e.g. `"kanchi"`) and any
/// `${github_repository.X.*}` reference target (the resource NAME, e.g.
/// `"akeyless_stack"`). These are the phantom-parent candidates: when a
/// child (label / branch-protection) is a create but its parent repo is a
/// NoOp in state, the parent is a likely phantom (in state, not in cloud).
#[must_use]
pub fn collect_suspect_repos(plan: &Plan) -> HashSet<String> {
    let mut names = HashSet::new();
    for c in &plan.resource_changes {
        if c.action == Action::NoOp {
            continue;
        }
        let Some(after) = &c.after else { continue };
        if let Some(serde_json::Value::String(r)) = after.get("repository") {
            names.insert(r.clone());
        }
        for refstr in collect_refs(after) {
            if let Some((ty, name)) = ref_target(&refstr) {
                if ty == "github_repository" {
                    names.insert(name);
                }
            }
        }
    }
    names
}

/// Below this many whole-resource drops in a single [`refresh_named`] pass,
/// the result is trusted outright — genuine phantoms are rare, individual
/// events. At or above it AND covering ≥ half the probed targets, the drop is
/// treated as a systemic `ReadResource` malfunction (provider auth/owner/
/// read-id, mass rate-limit miscoded as null) and SUPPRESSED. A real
/// deployment never loses half its resources between two plans.
const MASS_DROP_FLOOR: usize = 8;

/// The mass-drop guard's decision (pure, so it is unit-tested without a
/// provider). Returns `true` when the staged whole-resource drops should be
/// REFUSED — i.e. the drop is both absolutely non-trivial (`>= MASS_DROP_FLOOR`)
/// and covers at least half the probed targets. Such a pass is a systemic
/// `ReadResource` malfunction, not N genuine phantoms. See [`refresh_named`].
fn mass_drop_should_suppress(dropped: usize, targeted: usize) -> bool {
    dropped >= MASS_DROP_FLOOR && dropped.saturating_mul(2) >= targeted
}

/// Targeted, low-cost cousin of [`refresh_state`]: `ReadResource` ONLY the
/// resources of `type_id` whose resource-name OR `attributes["name"]` is in
/// `names`, dropping any the provider confirms **gone** (cty-null). Same
/// safety as [`refresh_state`] — NEVER drops on error/uncertainty, only on a
/// confirmed-null read — so the choice of `names` can be liberal without risk
/// (a wrong guess just costs an extra read). Reads are paced via `ctx.pacer`.
///
/// This heals PHANTOM parents: a repo recorded in state but never actually
/// created (whose children then fail `404` / unresolved-`${ref}`) is dropped,
/// so the next plan re-creates it. `names` is the small set of parents named
/// by the current plan's create-children, so this is a handful of reads — not
/// a full-state refresh (which would be ~1k RPCs).
pub async fn refresh_named(
    state: &mut State,
    type_id: &str,
    names: &HashSet<String>,
    ctx: &ApplyContext,
) -> RefreshReport {
    let mut report = RefreshReport::default();
    if names.is_empty() {
        return report;
    }
    let mut registry = Registry::new(ctx);
    let pacer = ctx.pacer.clone();
    let mut kept: Vec<StateResource> = Vec::new();
    // Whole-resource drops are STAGED, not applied, so the mass-drop guard
    // below can restore them if the read looks systemically broken.
    let mut staged_drop: Vec<StateResource> = Vec::new();
    let mut targeted: usize = 0;

    for resource in std::mem::take(&mut state.resources) {
        let attr_name = resource
            .instances
            .first()
            .and_then(|i| i.attributes.get("name"))
            .and_then(serde_json::Value::as_str);
        let is_target = resource.address.type_id.0 == type_id
            && (names.contains(&resource.address.name)
                || attr_name.is_some_and(|n| names.contains(n)));
        if !is_target {
            kept.push(resource);
            continue;
        }
        targeted += 1;

        let type_name = resource.address.type_id.0.clone();
        let provider_name = provider_local_name(&type_name);
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
        let mut gone_instances: Vec<StateInstance> = Vec::new();
        for inst in resource.instances {
            let prior_dv = match DynamicValue::from_json(&inst.attributes, &implied) {
                Ok(d) => d,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            if let Some(p) = pacer.as_deref() {
                let _ = p.acquire().await;
            }
            let lp = match registry.get(&provider_name).await {
                Ok(l) => l,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            match rpc_retry!(pacer.as_deref(), lp.conn.read_resource(&type_name, &prior_dv)) {
                Ok(None) => {
                    // Provider confirms gone — STAGE the instance for dropping.
                    // The mass-drop guard (below) may yet restore it if the
                    // whole pass looks like a systemic read malfunction.
                    report.dropped_instances += 1;
                    gone_instances.push(inst);
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
        if kept_instances.is_empty() && !gone_instances.is_empty() {
            // Every instance read gone — STAGE the whole-resource drop so the
            // guard can decide. (A resource with zero instances and no gones
            // falls through to the keep path unchanged.)
            report.dropped_resources += 1;
            staged_drop.push(StateResource {
                instances: gone_instances,
                ..resource
            });
        } else {
            kept.push(StateResource {
                instances: kept_instances,
                ..resource
            });
        }
    }

    // ── Mass-drop safety guard (attractor invariant) ─────────────────────
    // "Drop only on confirmed-gone" is safe ONLY if ReadResource is reliable.
    // If a large fraction of probed targets all read "gone" in a single pass,
    // that is not N genuine phantoms — it is a systemic read malfunction
    // (provider auth/owner/read-id, mass rate-limit miscoded as cty-null, …).
    // Honoring it corrupts state into a false-drop → +N-create → adopt
    // oscillation that never converges. So when the staged drop is both
    // absolutely non-trivial AND covers ≥ half the probed targets, REFUSE it:
    // restore everything and surface the malfunction via `suppressed_mass_drop`.
    let suppress = mass_drop_should_suppress(report.dropped_resources, targeted);
    if suppress {
        report.suppressed_mass_drop = report.dropped_resources;
        report.dropped_resources = 0;
        report.dropped_instances = 0;
        kept.append(&mut staged_drop);
    }
    state.resources = kept;
    report
}

/// Does a provider error message indicate the resource already exists
/// (a create-conflict to be adopted via import, not a hard failure)?
/// Matches the GitHub provider's 422 shapes ("name already exists on this
/// account", "has already been blocked") + generic already-exists/409.
fn is_already_exists(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already exists")
        || m.contains("already been")
        || m.contains("name_already_in_use")
        || m.contains("422")
        || m.contains("409")
}

/// The provider-native import id for a create-conflict adoption. Most
/// providers key import on the `name` attribute (github_repository's id IS
/// its name); fall back to the resource's address name.
fn natural_import_id(change: &ResourceChange) -> Option<String> {
    change
        .after
        .as_ref()
        .and_then(|a| a.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| Some(change.address.name.clone()))
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

    // Pace the upcoming mutation RPCs under the provider's secondary rate
    // limit. Cloned (cheap Arc) before the mutable `reg` borrow below.
    // NoOps returned above never reach here, so all-matched cycles pay
    // zero pacing latency.
    let pacer = reg.ctx.pacer.clone();
    if let Some(p) = pacer.as_deref() {
        let _ = p.acquire().await;
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
            rpc_retry!(pacer.as_deref(), lp
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
            let planned_dv = rpc_retry!(pacer.as_deref(), lp.conn.plan_resource_change(
                &type_name,
                &prior_dv,
                &config_dv,
                &config_dv
            ))
            .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?;
            let new_dv = match rpc_retry!(pacer.as_deref(), lp.conn.apply_resource_change(
                &type_name,
                &prior_dv,
                &planned_dv,
                &config_dv
            )) {
                Ok(dv) => dv,
                Err(e) => {
                    let msg = e.to_string();
                    // Import-on-conflict: a Create whose provider returns an
                    // "already exists" diagnostic (e.g. GitHub 422) means the
                    // resource EXISTS in cloud but is absent from magma's
                    // state. Adopt it via ImportResourceState instead of
                    // failing — otherwise the plan re-creates it every cycle
                    // and 422-loops forever (the pleme-io-opensource
                    // created:0 / all-422 wedge). This is the magma analog of
                    // tofu's importPolicy.autoOnConflict.
                    if change.action == Action::Create && is_already_exists(&msg) {
                        if let Some(id) = natural_import_id(change) {
                            if let Ok(Some(imp_dv)) =
                                lp.conn.import_resource_state(&type_name, &id).await
                            {
                                // ImportResourceState returns a STUB (the id +
                                // minimal fields). The terraform import protocol
                                // requires a follow-up ReadResource to populate
                                // the full current attributes (node_id, name,
                                // …). Skipping it leaves computed attrs empty, so
                                // dependents referencing them (e.g.
                                // github_branch_protection.repository_id =
                                // github_repository.X.node_id) resolve to "" and
                                // fail with "Could not resolve to a node with the
                                // global id of ''". Refresh the stub; fall back
                                // to it only if the read can't confirm.
                                let full_dv = match lp
                                    .conn
                                    .read_resource(&type_name, &imp_dv)
                                    .await
                                {
                                    Ok(Some(read_dv)) => read_dv,
                                    _ => imp_dv,
                                };
                                let attrs = full_dv
                                    .to_json(&implied)
                                    .map_err(|e| EngineError::Cty(e.to_string()))?;
                                insert_resource(state, &change.address, attrs.clone());
                                tracing::info!(
                                    address = ?change.address,
                                    import_id = %id,
                                    "magma apply: adopted pre-existing resource via import-on-conflict + ReadResource refresh (was already-exists)"
                                );
                                return Ok(AppliedChange {
                                    address: change.address.clone(),
                                    action: change.action,
                                    before: None,
                                    after: Some(attrs),
                                });
                            }
                        }
                    }
                    return Err(EngineError::Rpc(provider_name.clone(), msg));
                }
            };
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

/// Insert a data-source result under the `data` head, so a reference like
/// `${data.cloudflare_zones.z.result[0].id}` (head = `data`) resolves — distinct
/// from `sm_insert`'s `type → name` shape for managed resources.
fn sm_insert_data(
    sm: &mut HashMap<String, serde_json::Value>,
    addr: &ResourceAddress,
    attrs: &serde_json::Value,
) {
    let data = sm
        .entry("data".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let serde_json::Value::Object(by_type) = data {
        let t = by_type
            .entry(addr.type_id.0.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(by_name) = t {
            by_name.insert(addr.name.clone(), attrs.clone());
        }
    }
}

/// Evaluate one data source: encode its config against the DATA-SOURCE schema,
/// call `ReadDataSource`, decode the result to JSON (for `sm_insert_data`).
async fn read_data_source_one(
    change: &ResourceChange,
    reg: &mut Registry<'_>,
) -> Result<serde_json::Value, EngineError> {
    let pacer = reg.ctx.pacer.clone();
    if let Some(p) = pacer.as_deref() {
        let _ = p.acquire().await;
    }
    let type_name = change.address.type_id.0.clone();
    let provider_name = provider_local_name(&type_name);
    let lp = reg.get(&provider_name).await?;
    let implied = lp
        .schema
        .data_source(&type_name)
        .ok_or_else(|| EngineError::NoResourceSchema(type_name.clone(), provider_name.clone()))?
        .clone();
    let config_json = change.after.clone().unwrap_or(serde_json::Value::Null);
    let config_dv = DynamicValue::from_json(&config_json, &implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
    let state_dv = lp
        .conn
        .read_data_source(&type_name, &config_dv)
        .await
        .map_err(|e| EngineError::Rpc(provider_name.clone(), e.to_string()))?
        .ok_or_else(|| {
            EngineError::Rpc(
                provider_name.clone(),
                format!("data source {type_name} returned null state"),
            )
        })?;
    state_dv
        .to_json(&implied)
        .map_err(|e| EngineError::Cty(e.to_string()))
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
    fn mass_drop_guard_suppresses_systemic_read_failure() {
        // The live pleme-io-opensource bug: 661 existing repos all read "gone"
        // in one pass → must be refused (systemic ReadResource malfunction).
        assert!(mass_drop_should_suppress(661, 661));
        // Whole suspect set going gone at once → refuse regardless of size.
        assert!(mass_drop_should_suppress(MASS_DROP_FLOOR, MASS_DROP_FLOOR));
        // Half the probed targets going gone → refuse (boundary, inclusive).
        assert!(mass_drop_should_suppress(MASS_DROP_FLOOR, MASS_DROP_FLOOR * 2));
    }

    #[test]
    fn mass_drop_guard_trusts_genuine_phantoms() {
        // Nothing dropped → never suppress.
        assert!(!mass_drop_should_suppress(0, 1000));
        // A handful of real phantoms among many healthy targets → honor it.
        assert!(!mass_drop_should_suppress(2, 600));
        assert!(!mass_drop_should_suppress(MASS_DROP_FLOOR - 1, MASS_DROP_FLOOR - 1));
        // At/above the floor but < half of probed targets → honor it.
        assert!(!mass_drop_should_suppress(MASS_DROP_FLOOR, MASS_DROP_FLOOR * 2 + 1));
    }

    #[test]
    fn apply_context_has_default_pacer() {
        // Every apply paces mutation RPCs by default (1 req/s).
        let ctx = ApplyContext::new(PathBuf::from("/tmp/x"));
        assert!(ctx.pacer.is_some(), "default ApplyContext must carry a pacer");
    }

    #[test]
    fn pace_rph_zero_disables_pacing() {
        let ctx = ApplyContext::new(PathBuf::from("/tmp/x")).with_pace_rph(0.0);
        assert!(ctx.pacer.is_none(), "rph<=0 disables the pacer");
        let ctx2 = ApplyContext::new(PathBuf::from("/tmp/x")).without_pacer();
        assert!(ctx2.pacer.is_none());
    }

    #[tokio::test]
    async fn pace_rph_sets_target_rate() {
        // 7200 rph at quota 1.0 → 120 rpm.
        let ctx = ApplyContext::new(PathBuf::from("/tmp/x")).with_pace_rph(7200.0);
        let bucket = ctx.pacer.expect("pacer present");
        assert!((bucket.target_rpm().await - 120.0).abs() < 0.01);
        // A rate-limit signal escalates pressure → effective rpm drops.
        bucket.record_headroom(0, 100).await;
        assert!(bucket.effective_rpm().await < bucket.target_rpm().await);
    }

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
    fn data_source_reference_resolution() {
        use magma_types::{ModulePath, ResourceKind, ResourceTypeId};
        use serde_json::json;
        // This is the rio-drive Cloudflare bug, captured as a unit test: a
        // managed resource references a `data` source result by index, e.g.
        // `${data.cloudflare_zones.quero.result[0].id}`. Before the data-source
        // read pass + `data` head insert, that string leaked verbatim into the
        // provider RPC → Cloudflare 400. It must now resolve.
        let mut sm: HashMap<String, serde_json::Value> = HashMap::new();

        // sm_insert_data folds a ReadDataSource result under the `data` head.
        let zones_addr = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Data,
            type_id: ResourceTypeId("cloudflare_zones".into()),
            name: "quero".into(),
            key: None,
        };
        sm_insert_data(
            &mut sm,
            &zones_addr,
            &json!({ "result": [ { "id": "0da42c8d2132a9ddaf714f9e7c920711", "name": "quero.cloud" } ] }),
        );
        let acct_addr = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Data,
            type_id: ResourceTypeId("cloudflare_accounts".into()),
            name: "main".into(),
            key: None,
        };
        sm_insert_data(
            &mut sm,
            &acct_addr,
            &json!({ "result": [ { "id": "acct-9f3" } ] }),
        );

        // ref_target keeps returning None for data refs (they're read up front,
        // never graph-ordered against managed resources).
        assert_eq!(ref_target("data.cloudflare_zones.quero.result[0].id"), None);

        // A managed tunnel config referencing both data sources, indexed.
        let mut after = json!({
            "zone_id": "${data.cloudflare_zones.quero.result[0].id}",
            "account_id": "${data.cloudflare_accounts.main.result[0].id}",
            "comment": "tunnel for ${data.cloudflare_zones.quero.result[0].name}",
        });
        substitute_refs(&mut after, &sm);
        assert_eq!(after["zone_id"], json!("0da42c8d2132a9ddaf714f9e7c920711"));
        assert_eq!(after["account_id"], json!("acct-9f3"));
        assert_eq!(after["comment"], json!("tunnel for quero.cloud"));
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

    #[test]
    fn phantom_parents_collected_and_dropped() {
        use magma_types::{
            InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind,
            ResourceTypeId, StateInstance, StateResource,
        };
        let mkfail = |type_id: &str, name: &str, reason: &str| FailedChange {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(type_id.into()),
                name: name.into(),
                key: None,
            },
            action: Action::Create,
            reason: reason.into(),
        };
        // A label 404 (parent repo gone) + an unresolved branch-protection ${ref}.
        let failed = vec![
            mkfail(
                "github_issue_label",
                "kanchi-label-bug",
                "provider \"github\" RPC: POST https://api.github.com/repos/pleme-io/kanchi/labels: 404 Not Found []: ",
            ),
            mkfail(
                "github_branch_protection",
                "akeyless_stack_main",
                "Could not resolve to a node with the global id of '${github_repository.akeyless_stack.node_id}'",
            ),
        ];
        let parents = collect_phantom_parents(&failed);
        assert!(parents.contains("kanchi"), "repo name from /repos/owner/kanchi/labels 404");
        assert!(parents.contains("akeyless_stack"), "resource name from the ${{github_repository.X}} ref");

        // A repo-CREATE 422 on /orgs/.../repos must NOT implicate a parent
        // (inverse-phantom — exists in cloud, not state — handled elsewhere).
        let inverse = vec![mkfail(
            "github_repository",
            "breathe",
            "POST https://api.github.com/orgs/pleme-io/repos: 422 Repository creation failed [name already exists]",
        )];
        assert!(collect_phantom_parents(&inverse).is_empty(), "repo-create 422 is not a phantom signal");

        let mkrepo = |rname: &str, attr: &str| StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId("github_repository".into()),
                name: rname.into(),
                key: None,
            },
            provider: ProviderReference {
                source: "integrations/github".into(),
                name: "github".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                schema_version: 0,
                attributes: serde_json::json!({ "name": attr }),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        };
        let mut state = State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![
                mkrepo("kanchi", "kanchi"),               // phantom → dropped
                mkrepo("akeyless_stack", "akeyless-stack"), // phantom (addr-name match) → dropped
                mkrepo("galho", "galho"),                 // not implicated → kept
            ],
        };
        let dropped = drop_repos_from_state(&mut state, &parents);
        assert_eq!(dropped, 2, "kanchi + akeyless_stack dropped");
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.name, "galho", "non-phantom survives");
    }
}
