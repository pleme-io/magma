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
use std::time::Instant;

use chrono::Utc;
use magma_config::resolve_reference;
use samba::LeakyBucket;
use magma_cty::{CtyType, DynamicValue};
use magma_graph::ResourceGraph;
use magma_plugin::provider::{ProviderConn, ProviderSchema, is_retryable};
use magma_plugin::{Plugin, PluginSpec, ProviderCrash};
use magma_types::{
    Action, Plan, ResourceAddress, ResourceChange, ResourceKind, State, StateInstance,
    StateResource,
};

use crate::checkpoint::CheckpointSink;
use crate::cursor::{ApplyCursor, CycleOutcome, CycleStats, Progress, Quantum, Resume};
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
    /// The provider SUBPROCESS crashed (e.g. SIGSEGV nil-deref) during an
    /// RPC. Distinct from [`EngineError::Rpc`] so the operator's anomaly
    /// classifier matches a TYPED crash structurally — never by
    /// substring-guessing an opaque "channel closed". `detail` carries the
    /// captured panic line (+ the originating RPC error) so the cause is
    /// precise, not a dead-end transport string.
    #[error("provider {provider:?} crashed during {op}: {detail}")]
    ProviderCrashed {
        provider: String,
        op: String,
        detail: String,
    },
    #[error("provider {1:?} has no schema for resource type {0:?}")]
    NoResourceSchema(String, String),
    #[error("cty encode/decode: {0}")]
    Cty(String),
}

/// Build a crash-aware [`EngineError`] from a failed provider RPC. ONE
/// place all six provider RPC kinds (get_schema, configure, plan, apply,
/// read_data_source, import) funnel their transport failures through, so
/// every one gets identical treatment:
///
/// 1. If the provider subprocess CRASHED (its stderr captured a
///    panic/SIGSEGV/fatal line — `crash` is `Some`), return the TYPED
///    [`EngineError::ProviderCrashed`] carrying the panic line + the
///    originating RPC error. The operator's anomaly classifier matches
///    this variant structurally.
/// 2. Else if the h2 connection recorded a close reason (TLS/mTLS
///    rejection, EOF, broken pipe), fold it into the [`EngineError::Rpc`]
///    message so "channel closed" gains its real cause.
/// 3. Else a plain [`EngineError::Rpc`] with the op + error.
///
/// Takes the crash summary + close reason as plain `Option`s (read off
/// the `Plugin` at the call site) rather than borrowing the `Plugin`, so
/// it is unit-testable without a live provider and free of borrow-order
/// friction.
fn rpc_error(
    provider: &str,
    op: &str,
    crash: Option<ProviderCrash>,
    close_reason: Option<String>,
    err: &str,
) -> EngineError {
    if let Some(c) = crash {
        // Prefer the human-meaningful panic header; fall back to the raw
        // error when nothing was captured.
        let panic = c.headline().map(str::to_string).unwrap_or_else(|| err.to_string());
        let sig = c
            .signal
            .map(|s| format!(" (signal {s})"))
            .unwrap_or_default();
        // The crash SITE (`…/file.go:NNN`) names the exact provider line
        // that faulted — the single most actionable diagnostic. Surface it
        // inline so the operator log roots-causes the panic without a
        // separate trace-level archaeology pass.
        let site = c
            .crash_site()
            .map(|s| format!(" at {s}"))
            .unwrap_or_default();
        return EngineError::ProviderCrashed {
            provider: provider.to_string(),
            op: op.to_string(),
            detail: format!("{panic}{sig}{site} (rpc error: {err})"),
        };
    }
    match close_reason {
        Some(why) => EngineError::Rpc(
            provider.to_string(),
            format!("{op}: {err} (connection closed: {why})"),
        ),
        None => EngineError::Rpc(provider.to_string(), format!("{op}: {err}")),
    }
}

/// Read the crash summary + h2 close reason off a [`LiveProvider`]'s
/// plugin handle. Both are best-effort enrichment; either may be `None`.
fn provider_failure_signals(lp: &LiveProvider) -> (Option<ProviderCrash>, Option<String>) {
    let crash = lp._plugin.crash_summary();
    let close = lp._plugin.channel().and_then(|c| c.close_reason());
    (crash, close)
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
///
/// `pub` (crate-external) + `pub(crate)` fields so other magma-apply
/// modules — chiefly [`crate::import_prepass::ConfiguredImportEnvironment`]
/// — can hold + drive a `LiveProvider` dialed via
/// [`dial_configured_provider`] without duplicating the spawn →
/// handshake → dial → schema → configure lifecycle [`Registry::spawn`]
/// used to own exclusively.
pub struct LiveProvider {
    pub(crate) _plugin: Plugin,
    pub(crate) conn: ProviderConn,
    pub(crate) schema: ProviderSchema,
}

/// Spawn + fully configure a provider by its local name (e.g.
/// `"github"`) — locate the binary, spawn it, negotiate the
/// tfplugin5/6 handshake, dial, fetch its schema, then run
/// `ConfigureProvider`/`Configure` with `ctx`'s per-provider config
/// (or an empty config object, never null — providers expect a value
/// of the config type).
///
/// This is the ONE correct way to obtain a provider connection capable
/// of ANY RPC beyond `GetProviderSchema`. The Terraform plugin
/// protocol requires `Configure` to run before any other provider RPC
/// (`PlanResourceChange`, `ApplyResourceChange`, `ReadResource`,
/// `ImportResourceState`, …) — providers built on both SDKv2 and
/// terraform-plugin-framework cache their API client / credentials
/// during `Configure` and are not guaranteed to behave correctly (some
/// nil-dereference, see [`crate::engine`]'s module doc on the absent
/// `ClientCapabilities` SIGSEGV) when called unconfigured.
///
/// Extracted from [`Registry::spawn`]'s body so every caller — the
/// apply engine's own `Registry`, and the import prepass's
/// `ConfiguredImportEnvironment` — shares this ONE lifecycle instead of
/// each re-implementing spawn/handshake/dial/configure.
pub async fn dial_configured_provider(
    ctx: &ApplyContext,
    name: &str,
) -> Result<LiveProvider, EngineError> {
    let binary = magma_providers::locate_provider(&ctx.workspace_dir, name)
        .map_err(|e| EngineError::Locate(name.into(), e.to_string()))?;
    let mut plugin = Plugin::spawn(PluginSpec {
        binary,
        // Plaintext h2c (PluginSpec default `secure: false`): a
        // co-located subprocess provider serves plaintext over its
        // process-local socket when PLUGIN_CLIENT_CERT is unset
        // (standard go-plugin), and the socket is already the trust
        // boundary. AutoMTLS is opt-in for remote providers — a real
        // protocol-6 provider (cloudflare v5) closes the mTLS channel
        // post-handshake today, which is why the default is plaintext;
        // see magma-plugin PluginSpec.secure.
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
    let mut conn = ProviderConn::new(channel.clone(), protocol);
    // When a provider RPC fails with an opaque transport error
    // ("Service was not ready: channel closed"), the REAL cause is
    // either the provider subprocess CRASHING (stderr panic/SIGSEGV
    // captured on the plugin) or the h2 connection-close reason the
    // driver task recorded (TLS/mTLS rejection, EOF). Fold BOTH into
    // the typed error via the shared `rpc_error` helper so the failure
    // is precise, not a dead-end "channel closed". (Spawn-time has no
    // `LiveProvider` yet, so read the signals off `plugin` + `channel`
    // directly.)
    let spawn_err = |op: &str, e: String| -> EngineError {
        rpc_error(name, op, plugin.crash_summary(), channel.close_reason(), &e)
    };
    let schema = conn
        .get_schema()
        .await
        .map_err(|e| spawn_err("get_schema", e.to_string()))?;

    // Configure: the provider-config-typed creds, or an empty object
    // (→ a provider-config object with all attributes null, which is
    // what terraform sends for an absent provider block; the provider
    // falls back to its own env credentials). NOT a null object —
    // providers expect a value of the config type, not nil.
    let config_json = ctx
        .provider_configs
        .get(name)
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    let config_dv = DynamicValue::from_json(&config_json, &schema.provider_config)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
    conn.configure(&config_dv, &ctx.terraform_version)
        .await
        .map_err(|e| spawn_err("configure", e.to_string()))?;

    Ok(LiveProvider {
        _plugin: plugin,
        conn,
        schema,
    })
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
        // The provider is in the map (just inserted, or already present).
        // `ok_or_else` keeps this unwrap-free: the `None` arm is logically
        // unreachable but yields a typed error rather than a panic if that
        // invariant is ever broken (a provider on the apply path must never
        // panic magma).
        self.live.get_mut(name).ok_or_else(|| {
            EngineError::Spawn(
                name.to_string(),
                "internal: provider missing from registry after insert".to_string(),
            )
        })
    }

    async fn spawn(&self, name: &str) -> Result<LiveProvider, EngineError> {
        dial_configured_provider(self.ctx, name).await
    }
}

/// Apply a plan against `state` by driving the real providers. Mirrors
/// [`crate::run_plan`]'s outcome shape so the operator's `MagmaExecutor`
/// can swap one for the other.
///
/// This is the unbounded, run-to-completion entry point: exactly
/// [`run_plan_with_providers_resumable`] with no cursor and no quantum, so its
/// behaviour is identical to before resumption existed. Callers that need
/// bounded cycles — i.e. a plan too large to finish inside one window — call
/// the resumable form directly.
pub async fn run_plan_with_providers(
    plan: &Plan,
    state: &mut State,
    ctx: &ApplyContext,
) -> ApplyOutcome {
    // No quantum ⇒ no yield point ⇒ `Completed` is the only reachable arm.
    // `into_outcome` keeps this wrapper total instead of asserting that.
    // No checkpoint sink ⇒ nothing is written mid-cycle, so this path is
    // byte-identical to the pre-resumption engine.
    run_plan_with_providers_resumable(plan, state, ctx, None, None, None)
        .await
        .into_outcome()
}

/// Apply a plan in **bounded cycles**, so plan size stops governing whether
/// the apply can converge.
///
/// # Why this exists
///
/// The all-or-nothing apply made convergence conditional on the whole plan
/// fitting inside the caller's deadline. Past that size it could never
/// succeed, and each timeout discarded everything it had done. Here a cycle
/// does bounded work, records it in an [`ApplyCursor`], and *yields*; the next
/// cycle resumes at the frontier. N cycles converge for any N.
///
/// # How resumption stays correct
///
/// A resumed cycle must still resolve `${type.name.attr}` references that
/// point at resources an *earlier* cycle applied. It can, without any new
/// machinery, because those resources are in `state` and the resolution map is
/// seeded from `state` on entry — `State` is already the durable carrier of
/// applied attributes. Deferred data-source reads are the one exception: they
/// live only in the resolution map, never in `state`, and each costs a
/// rate-limiter token. Those ride the cursor instead, which is what stops a
/// resumed cycle re-paying the whole read prologue before it can reach new
/// work.
///
/// Already-completed addresses are never added to the dependency graph, so
/// they are not in any wave and have no path to execution — re-application is
/// structurally impossible rather than guarded by a runtime check.
///
/// # How progress survives a crash
///
/// Yielding a cursor at the end of a cycle only bounds the loss at one *cycle*
/// — a process killed mid-cycle (spot reclaim, OOM, node roll) takes the whole
/// record with it. Pass a [`CheckpointSink`] and the engine durably records
/// `(state, cursor)` after **every** node it applies and every deferred read it
/// caches, so at most one node's work is ever unrecorded.
///
/// The sink takes both halves in one call because the failure directions are
/// not symmetric: a cursor written ahead of state makes a resumed cycle *skip*
/// a resource that was never created — a silent drop — whereas state written
/// ahead of the cursor merely re-attempts, which adopt-on-conflict absorbs.
/// See [`crate::checkpoint`] for the full argument.
///
/// A checkpoint that fails stops the cycle. Continuing would grow the set of
/// nodes whose work is not durably recorded, which is exactly the quantity
/// checkpointing exists to bound.
///
/// # What this does not promise
///
/// The quantum is only ever checked *between* nodes; an in-flight provider RPC
/// is never cancelled. That is deliberate — cancelling mid-RPC would widen the
/// window in which a create commits provider-side without being recorded. That
/// window still exists (cloud I/O is not transactional), so the guarantee here
/// is at-least-once with typed adopt-on-conflict, not exactly-once. What
/// per-node checkpointing buys is that the window shrinks from a whole cycle to
/// one node.
pub async fn run_plan_with_providers_resumable(
    plan: &Plan,
    state: &mut State,
    ctx: &ApplyContext,
    resume: Option<Resume<'_>>,
    quantum: Option<Quantum>,
    checkpoint: Option<&dyn CheckpointSink>,
) -> CycleOutcome {
    let started_at = Utc::now();
    let cycle_start = Instant::now();
    let deadline = quantum.map(|q| cycle_start + q.as_duration());

    // `Resume` can only be minted by `ApplyCursor::resume(plan)`, so a cursor
    // for a different plan cannot reach this point.
    let mut cursor = match resume {
        Some(r) => r.cursor().clone(),
        None => ApplyCursor::empty(plan.id),
    };
    // Addresses this cycle newly recorded — the non-empty witness a yield
    // needs. Includes newly-cached data reads, because those are real durable
    // advances too.
    let mut progressed: Vec<ResourceAddress> = Vec::new();
    let mut stats = CycleStats {
        quantum_ms: quantum.map(Quantum::as_millis),
        ..CycleStats::default()
    };

    // Set when the quantum runs out during the deferred-read prologue. The
    // managed phase is then skipped wholesale — see the break site for why a
    // partially-populated resolution map is a correctness hazard, not just an
    // incomplete one.
    let mut prologue_exhausted = false;
    // Set when a checkpoint could not be made durable. Treated exactly like an
    // exhausted quantum: stop doing work, keep what we have, hand the caller a
    // cursor. Pressing on would grow the set of nodes whose work is not
    // durably recorded, which is the quantity checkpointing exists to bound.
    let mut checkpoint_failed = false;

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

    // Split the plan into (data sources, NoOp managed, real managed). Data
    // sources are evaluated up front (ReadDataSource) so their results populate
    // the resolution map under `data.<type>.<name>` BEFORE any managed resource
    // that references them is applied. See `partition_changes` for why the
    // data-kind split MUST precede the NoOp split.
    let (datas, noops, reals) = partition_changes(&plan.resource_changes);

    for change in noops {
        // A NoOp returns before any RPC or state write, so this record is
        // empty in practice. Committing it anyway keeps the call total: if
        // `partition_changes` ever routes a non-NoOp through here, its writes
        // reach state instead of being silently dropped.
        let mut rec = NodeRecord::default();
        let outcome = apply_one(change, &mut rec, &mut registry).await;
        rec.commit(state);
        match outcome {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(mkfail(change, e)),
        }
    }

    // Resolve each data source + fold its result into state_map under the
    // `data` head, so `${data.<type>.<name>.<attr>}` references resolve in the
    // managed pass below. (Data sources are not graph-ordered — they have no
    // computed deps on managed resources; ref_target deliberately returns None
    // for them.)
    for change in &datas {
        // REACTION C — an ORPHANED data source (in state/`before` but ABSENT
        // from the rendered config, so the plan gave it `Delete`/`Forget`) is
        // FORGOTTEN, never re-read. A data source is definitionally a *cache of
        // a read*; a removed one has no config left to read against, so there
        // is nothing to refresh — it is simply dropped from state. This makes
        // the orphan-refresh-crash class UNREPRESENTABLE: the only caller of
        // `read_data_source_one` is below in this loop, and a removed data
        // source `continue`s out before reaching it — no code path RPC-reads a
        // data source that is no longer in config. (Before this branch, an
        // orphaned `cloudflare_accounts`/`cloudflare_zones` list data source
        // fell through to the read path with a null `after` config; the
        // cloudflare 5.19.1 provider nil-derefs on it, the provider PROCESS
        // dies, and the whole cycle cascade-fails "channel closed" — the exact
        // wedge that required a manual Postgres `UPDATE` to purge the orphan
        // rows from state. That manual purge is now an in-engine reaction.)
        if matches!(change.action, Action::Delete | Action::Forget) {
            remove_resource(state, &change.address);
            applied.push(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: None,
            });
            tracing::info!(
                address = ?change.address,
                action = ?change.action,
                "magma apply: forgot orphaned data source (removed from config; \
                 dropped from state without a provider read)"
            );
            continue;
        }
        // A NoOp data source whose value is ALREADY resolved in `before`
        // carries that value forward — terraform does not re-read a data
        // source whose config was fully known + read at plan time. Re-reading
        // it at apply is not just wasteful: the plan's `after` for a NoOp data
        // source is null, so a re-read would hand the provider a null/empty
        // config (e.g. a null `name` filter) and some providers nil-deref on
        // it (the live cloudflare 5.13.0 `cloudflare_zones`/`cloudflare_accounts`
        // SIGSEGV). Reuse the resolved `before` state instead — the planned
        // read result the data source already holds.
        if change.action == Action::NoOp {
            if let Some(before) = change.before.as_ref().filter(|b| !b.is_null()) {
                sm_insert_data(&mut state_map, &change.address, before);
                applied.push(AppliedChange {
                    address: change.address.clone(),
                    action: change.action,
                    before: Some(before.clone()),
                    after: Some(before.clone()),
                });
                continue;
            }
        }
        // A deferred read an earlier cycle already performed is served from the
        // cursor. Each of these costs a rate-limiter token and is NOT persisted
        // in `state` (only in the resolution map), so without this cache every
        // resumed cycle would re-pay the whole read prologue before reaching
        // any new work — which is precisely how naive chunking livelocks.
        if let Some(cached) = cursor.data_result(&change.address) {
            sm_insert_data(&mut state_map, &change.address, cached);
            stats.data_reads_cached += 1;
            applied.push(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: None,
                after: Some(cached.clone()),
            });
            continue;
        }
        // Out of quantum mid-prologue. Stop here and let the managed phase be
        // skipped entirely: the resolution map is incomplete, and substituting
        // references against a half-populated map would apply *wrong values*,
        // not merely fewer of them.
        if past_deadline(deadline) {
            prologue_exhausted = true;
            break;
        }
        // A genuinely-unread data source (deferred read: config depended on a
        // resource only now created) IS read via RPC — resolve refs in its
        // config first (usually literal).
        let mut resolved = (*change).clone();
        if let Some(after) = resolved.after.as_mut() {
            substitute_refs(after, &state_map);
        }
        // Counted before the call, not in the success arm: an attempted read
        // spends a rate-limiter token whether or not it succeeds, and this
        // number exists to measure the prologue's real cost.
        stats.data_reads_performed += 1;
        match read_data_source_one(&resolved, &mut registry).await {
            Ok(result) => {
                sm_insert_data(&mut state_map, &change.address, &result);
                // Caching a read is durable progress in its own right — a
                // workspace whose prologue is dominated by paced reads advances
                // by exactly this each cycle, and calling that a stall would
                // hide a working system.
                // Make the read durable before spending another token. A read
                // costs a rate-limiter second, so losing one is a second of
                // prologue the next cycle re-pays — the very cost the cursor's
                // read cache exists to remove.
                let recorded = record_data_read(
                    &mut cursor,
                    &change.address,
                    &result,
                    state,
                    checkpoint,
                    &mut stats,
                )
                .await;
                if recorded.advanced() {
                    progressed.push(change.address.clone());
                }
                applied.push(AppliedChange {
                    address: change.address.clone(),
                    action: change.action,
                    before: None,
                    after: Some(result),
                });
                if recorded == Recorded::Undurable {
                    checkpoint_failed = true;
                    break;
                }
            }
            Err(e) => failed.push(mkfail(change, e)),
        }
    }

    // Everything above is the cycle's fixed cost: seeding the resolution map,
    // resolving deferred reads, and (just below) building the graph. Chunked
    // resumption converges only while this fits inside the quantum with room
    // for at least one node, so it is the quantity a derived quantum must be
    // sized against — hence recording it rather than inferring it later.
    stats.prologue_ms = elapsed_ms(cycle_start);

    // Build the dependency graph from ${type.name.attr} references that point
    // at OTHER real changes, so each resource is applied before anything that
    // consumes its computed attributes (node_id, id, …).
    //
    // Anything the cursor already records as applied is EXCLUDED here. That is
    // what makes re-application structurally impossible rather than
    // runtime-guarded: an excluded address is in no wave and in no `by_key`
    // lookup, so no code path below can execute it. Its computed attributes
    // still resolve for dependents, because they were written into `state` when
    // it was applied and the resolution map is seeded from `state` on entry.
    //
    // The exclusion tests `covers`, not `contains`: the cursor must have
    // recorded *this* change (address AND content fingerprint), not merely
    // something at this address. Dropping a real change because an older,
    // different change to the same resource was recorded would be a silent
    // no-op reported as success.
    let pending: Vec<&ResourceChange> = cursor.frontier(reals.iter().copied());

    let real_keys: HashSet<(String, String)> = pending
        .iter()
        .map(|c| (c.address.type_id.0.clone(), c.address.name.clone()))
        .collect();
    let by_key: HashMap<(String, String), &ResourceChange> = pending
        .iter()
        .map(|c| ((c.address.type_id.0.clone(), c.address.name.clone()), *c))
        .collect();

    let mut graph = ResourceGraph::new();
    for c in &pending {
        graph.add(c.address.clone());
    }
    for c in &pending {
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

    // Topological waves, kept AS WAVES rather than flattened. Iterating
    // wave-major then within-wave visits addresses in exactly the order the
    // old `waves().flatten()` did, so execution is unchanged — but the width
    // of each wave (the available parallelism, which the flatten computed and
    // then threw away) survives to be used by the concurrent executor, and the
    // wave boundary gives the quantum a natural checkpoint.
    //
    // On a cycle / graph error, fall back to plan order as one big wave —
    // attempt the apply rather than refuse the whole cycle.
    let waves: magma_graph::Waves = if prologue_exhausted || checkpoint_failed {
        // The prologue was cut short — by the quantum, or by a checkpoint we
        // could not make durable — so the resolution map is incomplete.
        // Applying now would substitute *wrong* values, not merely fewer of
        // them. Do nothing this cycle and let the yield carry the reads we did
        // cache.
        magma_graph::Waves::empty()
    } else {
        match graph.waves() {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = %e, "magma: dependency-graph error — applying in plan order");
                // Plan order as ONE wave would assert an antichain that the
                // graph just failed to prove — and the concurrent executor
                // below would then run mutually-dependent changes at once.
                // Degrade to one address per wave instead: same plan order,
                // but every node is its own dependency step, so a graph error
                // costs parallelism and never correctness.
                magma_graph::Waves::sequential(pending.iter().map(|c| c.address.clone()))
            }
        }
    };
    stats.max_wave_width = waves.max_width();

    let mut out_of_quantum = prologue_exhausted || checkpoint_failed;
    'waves: for wave in &waves {
        stats.waves_entered += 1;
        for addr in wave.iter() {
            // The quantum is checked only BETWEEN nodes — an in-flight
            // provider RPC is never cancelled. Cancelling mid-RPC would widen
            // the window in which a create commits provider-side without being
            // recorded, which is the one hazard chunking is supposed to
            // shrink.
            if past_deadline(deadline) {
                out_of_quantum = true;
                break 'waves;
            }
            let key = (addr.type_id.0.clone(), addr.name.clone());
            let Some(change) = by_key.get(&key).copied() else {
                continue;
            };
            stats.nodes_attempted += 1;
            // Substitute ${ref}s against everything applied so far — including,
            // on a resumed cycle, everything earlier cycles wrote into `state`.
            let mut resolved = change.clone();
            if let Some(after) = resolved.after.as_mut() {
                substitute_refs(after, &state_map);
            }
            // `apply_one` RECORDS its state writes into `rec` rather than
            // performing them, so the write is applied here, at a point the
            // caller controls, immediately before the checkpoint. The commit
            // runs on BOTH arms: a replace that destroyed the old instance and
            // then failed to create its replacement has really destroyed it,
            // and state must say so.
            let mut rec = NodeRecord::default();
            let outcome = apply_one(&resolved, &mut rec, &mut registry).await;
            rec.commit(state);
            stats.pacer_wait_ms_total = stats
                .pacer_wait_ms_total
                .saturating_add(rec.pacer_wait_ms);
            stats.node_rpc_ms_total = stats.node_rpc_ms_total.saturating_add(rec.rpc_ms);
            stats.node_rpc_ms_max = stats.node_rpc_ms_max.max(rec.rpc_ms);
            match outcome {
                Ok(a) => {
                    if let Some(attrs) = &a.after {
                        // Provider-returned new_state feeds dependents' references.
                        sm_insert(&mut state_map, &change.address, attrs);
                    }
                    stats.nodes_completed += 1;
                    // Durability point. `state` carries this node's writes
                    // (just committed above), so the sink sees a consistent
                    // pair: everything the cursor claims, state proves.
                    // Checkpointing HERE rather than at the end of the cycle is
                    // what bounds a crash's loss at one node.
                    //
                    // The recorded change is the PLANNED one, not the
                    // ref-substituted clone: `covers` is tested against the
                    // plan's changes on a later cycle, and those are
                    // unsubstituted.
                    let recorded =
                        record_change(&mut cursor, change, state, checkpoint, &mut stats).await;
                    if recorded.advanced() {
                        progressed.push(change.address.clone());
                    }
                    applied.push(a);
                    if recorded == Recorded::Undurable {
                        checkpoint_failed = true;
                        out_of_quantum = true;
                        break 'waves;
                    }
                }
                // A failed change is deliberately NOT recorded as completed —
                // the next cycle retries it. Recording it would make the cursor
                // claim progress the cloud never made.
                Err(e) => failed.push(mkfail(change, e)),
            }
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

    let remaining = pending.len().saturating_sub(stats.nodes_completed);
    stats.nodes_remaining = remaining;
    stats.elapsed_ms = elapsed_ms(cycle_start);

    let partial = ApplyOutcome {
        plan_id: plan.id,
        state: state.clone(),
        applied,
        failed,
        started_at,
        finished_at: Utc::now(),
    };

    // Finished only if the cycle ran to the end of the graph AND nothing is
    // outstanding. `remaining > 0` covers both "ran out of quantum" and "some
    // changes failed and are due a retry"; either way the honest answer is
    // "run another cycle", which is what the non-`Completed` arms mean.
    if !out_of_quantum && remaining == 0 {
        return CycleOutcome::Completed {
            outcome: partial,
            stats,
        };
    }

    // Durability, not the quantum, ended this cycle. Say so plainly: the
    // remedy is a working checkpoint sink, and an operator reading only
    // "yielded" would otherwise go tuning the quantum, which cannot help.
    if checkpoint_failed {
        tracing::error!(
            checkpoint_failures = stats.checkpoint_failures,
            nodes_completed = stats.nodes_completed,
            nodes_remaining = remaining,
            "magma apply: cycle ended on a durability failure, not the quantum — \
             progress beyond this point would not have been recoverable"
        );
    }

    // The only place a yield-vs-stall verdict is made. `Progress::new` returns
    // `None` for an empty witness, so a cycle that advanced nothing CANNOT be
    // dressed up as a yield — it lands in `Stalled`, which says the quantum
    // cannot cover this cycle's fixed prologue and that retrying unchanged
    // will not converge.
    match Progress::new(progressed) {
        Some(progress) => CycleOutcome::Yielded {
            partial,
            cursor,
            progress,
            stats,
        },
        None => {
            tracing::warn!(
                prologue_ms = stats.prologue_ms,
                quantum_ms = ?stats.quantum_ms,
                nodes_remaining = remaining,
                "magma apply: cycle stalled — no durable progress; quantum cannot cover the prologue"
            );
            CycleOutcome::Stalled {
                partial,
                cursor,
                stats,
            }
        }
    }
}

/// True once the cycle's quantum has elapsed. `None` = unbounded, which is
/// what the run-to-completion wrapper passes.
fn past_deadline(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

/// What happened when a durable advance was recorded.
///
/// Three arms, not a `(bool, bool)` pair, because "did not advance but is not
/// durable" is not a thing that can happen — nothing is written when nothing
/// advanced — and a pair would let that state be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recorded {
    /// The cursor already had this. Nothing written, nothing to do.
    AlreadyPresent,
    /// Advanced and made durable. Carry on.
    Durable,
    /// Advanced, but the position could not be made durable. The caller must
    /// stop applying — the cursor is ahead of the store, and widening that gap
    /// is the one thing checkpointing exists to prevent.
    Undurable,
}

impl Recorded {
    /// Did the cursor move? True for both advance arms — an advance that could
    /// not be persisted is still an advance in memory, and the caller must
    /// count it as progress or it would mis-report a real change as a stall.
    fn advanced(self) -> bool {
        matches!(self, Recorded::Durable | Recorded::Undurable)
    }
}

/// Record an applied change and make the new position durable.
///
/// **The order is the invariant.** The cursor is advanced *before* the
/// checkpoint, so the sink always observes a position that already covers the
/// change whose effect is in `state`. Checkpointing first would hand the store
/// a cursor that omits work `state` reflects; on resume that node would be
/// re-attempted — the tolerable direction, but still the wrong one to bake in.
///
/// This is a named function rather than four inline lines specifically so the
/// ordering can be proved without a live provider: `Registry` spawns real
/// plugin subprocesses, so no unit test can produce a *successful* managed
/// apply through the engine's main loop.
async fn record_change(
    cursor: &mut ApplyCursor,
    change: &ResourceChange,
    state: &State,
    sink: Option<&dyn CheckpointSink>,
    stats: &mut CycleStats,
) -> Recorded {
    if !cursor.complete(change) {
        return Recorded::AlreadyPresent;
    }
    if checkpoint_now(sink, state, cursor, stats, "node").await {
        Recorded::Durable
    } else {
        Recorded::Undurable
    }
}

/// Record a deferred data-source read and make the new position durable.
///
/// Same ordering rule as [`record_change`]. A read is worth persisting even
/// though it changes no `state`: it costs a rate-limiter token, so losing one
/// is a second of prologue the next cycle has to re-pay.
async fn record_data_read(
    cursor: &mut ApplyCursor,
    address: &ResourceAddress,
    value: &serde_json::Value,
    state: &State,
    sink: Option<&dyn CheckpointSink>,
    stats: &mut CycleStats,
) -> Recorded {
    if !cursor.record_data(address.clone(), value.clone()) {
        return Recorded::AlreadyPresent;
    }
    if checkpoint_now(sink, state, cursor, stats, "data-read").await {
        Recorded::Durable
    } else {
        Recorded::Undurable
    }
}

/// Make the current `(state, cursor)` pair durable. Returns `false` if the
/// caller should stop applying.
///
/// `None` — no sink — is a *success*, not a skip-and-warn: an apply with no
/// sink is the pre-existing unbounded path, which never wrote anything
/// mid-cycle and must keep behaving exactly as it did.
///
/// A real failure is not propagated as an error, because the work already
/// applied must not be thrown away over a storage hiccup. It is reported, the
/// stat is bumped, and the cycle winds down with a cursor the caller can still
/// persist itself. What the caller must NOT do is keep applying, which is why
/// this returns a decision rather than a `Result` the call site could ignore.
async fn checkpoint_now(
    sink: Option<&dyn CheckpointSink>,
    state: &State,
    cursor: &ApplyCursor,
    stats: &mut CycleStats,
    site: &'static str,
) -> bool {
    let Some(sink) = sink else {
        return true;
    };
    match sink.checkpoint(state, cursor).await {
        Ok(()) => {
            stats.checkpoints_written += 1;
            true
        }
        Err(e) => {
            stats.checkpoint_failures += 1;
            tracing::error!(
                error = %e,
                site,
                completed = cursor.len(),
                "magma apply: checkpoint failed — stopping this cycle so the \
                 unrecorded set stays bounded"
            );
            false
        }
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
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
        // GATE THE PATH-SHAPE BRANCH ON 404 — necessary, because the shape
        // alone is NOT sufficient: a child's already-exists **422** carries the
        // very same `/repos/<owner>/<repo>/<child>` path as a genuine parent
        // 404. Ungated, a label that already exists was read as proof its
        // parent repository is a phantom, and `drop_repos_from_state` evicted a
        // repo that is perfectly real — 11 live repositories per failed apply on
        // pleme-io-opensource (state 2722 -> 2711, serial 36 -> 37), re-created
        // next plan, colliding again: a churn loop that never converged.
        //
        // The doc comment above already promised this ("Only repo-scoped 404
        // paths match"); the code never implemented it.
        //
        // Scoped to THIS branch only. The `${github_repository.X}` branch below
        // is a different signal — an unresolved reference means the parent is
        // genuinely absent from state regardless of any status code — so gating
        // it on 404 would break real phantom detection.
        let mut rest = if r.contains("404") { r } else { "" };
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

impl RefreshReport {
    /// The typed trust record this pass earned.
    ///
    /// The whole point of the conversion: these counters used to be
    /// printed to stderr and dropped on the floor, so an observation in
    /// which EVERY read failed (`kept_on_error = N`, state untouched, plan
    /// all-`NoOp`) was indistinguishable downstream from one in which
    /// reality genuinely matched. [`magma_types::Observation`] classifies
    /// the pass once, at the border, into a value a consumer must match on
    /// — see [`magma_types::Coverage`] and
    /// [`magma_types::Plan::drift_verdict`].
    ///
    /// **Scope follows the pass.** A report from [`refresh_state`] covers
    /// every instance in the state, so its observation describes the whole
    /// world. A report from [`refresh_named`] covers only the resources it
    /// targeted, so its observation is a statement about THAT SUBSET —
    /// `Complete` there means "every targeted read answered", never "the
    /// state is fully observed". Do not stamp a targeted pass onto a
    /// whole-state plan.
    #[must_use]
    pub fn observation(&self) -> magma_types::Observation {
        magma_types::Observation::of((*self).into())
    }
}

impl From<RefreshReport> for magma_types::RefreshCounts {
    /// Field-for-field. `RefreshReport` stays where the refresh lives;
    /// `RefreshCounts` is the border shape that travels on persisted
    /// artifacts, so `magma-types` never has to depend on the apply engine.
    fn from(r: RefreshReport) -> Self {
        Self {
            refreshed: r.refreshed,
            dropped_instances: r.dropped_instances,
            dropped_resources: r.dropped_resources,
            kept_on_error: r.kept_on_error,
            suppressed_mass_drop: r.suppressed_mass_drop,
        }
    }
}

/// Resolve `inst`'s prior [`DynamicValue`] for a `ReadResource`/refresh RPC.
///
/// When `inst.schema_version` already matches (or, in the never-observed
/// case of a provider that regressed its version, is newer than) the
/// provider's `current_version` for `type_name`, this is a direct decode
/// against `implied`. Otherwise `inst.attributes` was persisted under an
/// OLDER schema, and the terraform plugin protocol requires
/// `UpgradeResourceState` to migrate it forward BEFORE it is fed into
/// `ReadResource`/`PlanResourceChange`/`ApplyResourceChange` — decoding
/// old-schema JSON straight against a newer implied type (the entire
/// history of this function before this fix) risks a marshal mismatch or a
/// provider-side crash/misparse the moment a provider's schema evolves (a
/// routine occurrence for actively maintained providers). See
/// `magma_plugin::provider::ProviderConn::upgrade_resource_state`.
///
/// `Err(())` on any decode/RPC failure — every call site's uniform
/// response is "treat this instance as uncertain, keep it unchanged, count
/// it `kept_on_error`" (refresh must never drop or corrupt state because a
/// read/upgrade failed).
async fn resolve_prior_dv(
    lp: &mut LiveProvider,
    pacer: Option<&LeakyBucket>,
    type_name: &str,
    implied: &CtyType,
    current_version: i64,
    inst: &StateInstance,
) -> Result<DynamicValue, ()> {
    if (inst.schema_version as i64) < current_version {
        let raw = serde_json::to_vec(&inst.attributes).map_err(|_| ())?;
        rpc_retry!(
            pacer,
            lp.conn
                .upgrade_resource_state(type_name, inst.schema_version as i64, &raw)
        )
        .map_err(|_| ())
    } else {
        DynamicValue::from_json(&inst.attributes, implied).map_err(|_| ())
    }
}

/// Refresh `state` against the providers' ACTUAL current state — terraform's
/// plan-time refresh. For every resource instance, call `ReadResource`:
///
/// * provider reports it **gone** (cty-null) → drop the instance. This
///   self-heals phantom entries — e.g. a resource a prior structural-only
///   apply recorded in state but never actually created — so the next plan
///   re-creates it.
/// * provider returns refreshed state → update the instance's attributes
///   (so drift in real attributes is detected), stamping `schema_version`
///   to the provider's CURRENT version (migrating forward via
///   [`resolve_prior_dv`] first when the stored version was older).
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

        // Resolve the implied type + current schema version once (clone
        // so the schema borrow ends before the per-instance mutable RPC
        // borrows). Any failure here ⇒ keep the whole resource untouched.
        let (implied, current_version) = match registry.get(&provider_name).await {
            Ok(lp) => match lp.schema.resource(&type_name) {
                Some(t) => (t.clone(), lp.schema.resource_version(&type_name)),
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
            let lp = match registry.get(&provider_name).await {
                Ok(l) => l,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            let prior_dv =
                match resolve_prior_dv(lp, None, &type_name, &implied, current_version, &inst)
                    .await
                {
                    Ok(d) => d,
                    Err(()) => {
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
                            // Now confirmed current — never leave the stale
                            // stored version in place (that would silently
                            // re-trigger the same upgrade every cycle and
                            // never actually converge to "checked").
                            schema_version: u64::try_from(current_version)
                                .unwrap_or(inst.schema_version),
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
        let (implied, current_version) = match registry.get(&provider_name).await {
            Ok(lp) => match lp.schema.resource(&type_name) {
                Some(t) => (t.clone(), lp.schema.resource_version(&type_name)),
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
            // Migrates forward via UpgradeResourceState first when
            // `inst.schema_version` is older than `current_version` — see
            // `resolve_prior_dv`'s doc.
            let prior_dv = match resolve_prior_dv(
                lp,
                pacer.as_deref(),
                &type_name,
                &implied,
                current_version,
                &inst,
            )
            .await
            {
                Ok(d) => d,
                Err(()) => {
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
                            schema_version: u64::try_from(current_version)
                                .unwrap_or(inst.schema_version),
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

/// Terraform-parity plan-time refresh + plan — the ONE place a caller goes
/// instead of `magma_plan::plan` directly when it wants real Terraform's
/// implicit-refresh guarantee.
///
/// Real Terraform calls `ReadResource` against every state instance before
/// every `plan`/`apply`, specifically to catch out-of-band drift (a resource
/// deleted or edited outside the tool). Before this function existed, every
/// magma entry point diffed config against whatever `state` happened to be
/// on disk, so a manually-deleted resource surfaced as `NoOp` instead of the
/// `Create` it actually needs, and a manually-edited resource's drift was
/// invisible to the plan.
///
/// * `ctx = None` — refresh is skipped; behaves exactly like calling
///   `magma_plan::plan` directly (the pre-fix behavior, e.g. `--refresh
///   false`, or a caller with no way to reach real providers). Returns
///   `report = None`.
/// * `ctx = Some(ctx)` — [`refresh_state`] runs first. It NEVER drops an
///   instance on read failure or uncertainty (provider unreachable, no
///   schema, decode error — see its own docs), so it is always safe to pass
///   `Some` even when no provider binaries are cached: refresh degrades to a
///   report full of `kept_on_error` and the plan proceeds against
///   unchanged state, identical to the `ctx = None` path. Returns
///   `report = Some(_)` describing what changed.
///
/// This function mutates `state` in place (refreshed attributes / dropped
/// phantoms) but never persists it anywhere — callers that own a backend
/// are responsible for writing the (possibly refreshed) `state` back after
/// calling this, exactly as they already do with the plan's outcome.
pub async fn refresh_then_plan(
    cfg: &magma_config::Config,
    state: &mut State,
    ctx: Option<&ApplyContext>,
) -> Result<(Plan, Option<RefreshReport>), magma_plan::PlanError> {
    let report = match ctx {
        Some(ctx) => Some(refresh_state(state, ctx).await),
        None => None,
    };
    // Stamp the refresh's OWN trustworthiness onto the artifact that
    // survives. Without this the report died here — printed to stderr,
    // reduced to `.is_some()` — and a pass in which every `ReadResource`
    // failed produced a plan bit-indistinguishable from one in which
    // reality genuinely matched: same untouched state, same all-`NoOp`
    // change set, same bytes. Publishing that as reality is publishing a
    // lie. `Observation` is derived from the counts, never asserted, so
    // this can only ever narrow a claim.
    let observation = report.as_ref().map_or_else(
        magma_types::Observation::unrefreshed,
        RefreshReport::observation,
    );
    let plan = magma_plan::plan(cfg, state)?.with_observation(observation);
    Ok((plan, report))
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
///
/// COMPOSITE-KEYED types (2026-07-07): GitHub sub-resources do NOT key import
/// on a bare `name` — they key on `<parent>:<subkey>` (e.g.
/// `github_branch_protection` imports by `<repo>:<pattern>`, NOT its address
/// name "akeyless_stack_main"). Without the composite id, adopt-on-conflict
/// resolves the wrong import id, `import_resource_state` fails, and the
/// create-that-exists never adopts — the pleme-io-opensource "8 stuck creates /
/// all-422" wedge. These arms mirror the pangea-operator import.rs
/// `bundled_natural_ids` templates so magma's in-engine reactive adopt matches
/// the operator's proactive prepass. Non-github / name-keyed types fall through
/// to the original `name`/address-name behavior unchanged.
fn natural_import_id(change: &ResourceChange) -> Option<String> {
    let get = |k: &str| {
        change
            .after
            .as_ref()
            .and_then(|a| a.get(k))
            .and_then(|v| v.as_str())
    };
    // A sub-resource's `repository` field is authored as a typed reference to
    // its parent — `${github_repository.<name>.name}`. The plan's `after` holds
    // RAW config: reference substitution runs later in the create path, AFTER
    // import-id construction, so `get("repository")` here yields the literal
    // `${github_repository.izumi.name}`, not `izumi`. The parent repo's `.name`
    // attribute IS its resource name (the org-posture convention), so extract
    // `<name>` syntactically — exactly as `collect_phantom_parents` does. This
    // is state-independent: the import id resolves to `izumi:bug` whether or not
    // izumi's `github_repository` is currently in the state_map, so the existing
    // GitHub labels adopt instead of failing `${…}:bug` import → empty-repo 404
    // create → parent-phantom-drop loop (the izumi/asobi "8 stuck creates"
    // residual after the composite-key fix). An already-resolved value (no
    // `${github_repository.` prefix) passes through unchanged. NOTE: only `.name`
    // references deref this way — `github_branch_protection.repository_id` is a
    // `${…node_id}` reference whose value is NOT the name, so it keeps raw `get`.
    let deref_repo = |v: &str| -> String {
        v.strip_prefix("${github_repository.")
            .and_then(|rest| rest.split(['.', '}']).next())
            .filter(|s| !s.is_empty())
            .unwrap_or(v)
            .to_string()
    };
    let repo_get = |k: &str| get(k).map(deref_repo);
    let pair = |a: &str, b: &str| match (get(a), get(b)) {
        (Some(x), Some(y)) => Some(format!("{x}:{y}")),
        _ => None,
    };
    // `<repo>:<subkey>` where `<repo>` is a parent reference to deref.
    let pair_repo = |a: &str, b: &str| match (repo_get(a), get(b)) {
        (Some(x), Some(y)) => Some(format!("{x}:{y}")),
        _ => None,
    };
    let composite = match change.address.type_id.0.as_str() {
        // repository_id is a `${…node_id}` reference, NOT `.name` — keep raw.
        "github_branch_protection" => pair("repository_id", "pattern"),
        "github_actions_secret" => pair_repo("repository", "secret_name"),
        "github_actions_variable" => pair_repo("repository", "variable_name"),
        "github_repository_environment" => pair_repo("repository", "environment"),
        "github_issue_label" => pair_repo("repository", "name"),
        // Repo-scoped singletons import by the parent repo name.
        "github_repository_topics"
        | "github_repository_collaborators"
        | "github_actions_repository_permissions" => repo_get("repository"),
        _ => None,
    };
    composite
        .or_else(|| get("name").map(str::to_string))
        .or_else(|| Some(change.address.name.clone()))
}

/// Resolve the provider-native import id for adopting a create-conflicted
/// resource (an `is_already_exists` Create). Most providers key import on the
/// `name` attribute, so [`natural_import_id`] suffices. Some assign an OPAQUE
/// server id that is absent from config and only knowable by DISCOVERY — e.g.
/// `cloudflare_dns_record`'s import id is `<zone_id>/<record_id>`, and
/// `record_id` can only be found by listing the zone and matching the natural
/// key (name + type). This is the generic adopt-by-identity resolver: per-type
/// discovery via a provider read, falling back to the natural `name` id. A
/// discovery failure returns `None` so the caller falls through to the genuine
/// create-conflict failure — never an adoption with a wrong id.
///
/// New opaque-id resource types register a discovery arm here; this is the
/// extension point for the generic ObjectExistsUntracked → adopt reaction.
async fn resolve_import_id(
    change: &ResourceChange,
    type_name: &str,
    lp: &mut LiveProvider,
) -> Option<String> {
    // An opaque-id type registers an `AdoptionSpec`; the generic interpreter
    // discovers its id via a list-data-source read. Everything else keys
    // import on the natural `name`.
    match crate::adopt::spec_for(type_name) {
        Some(spec) => match discover_via_spec(&spec, change, lp).await {
            Ok(opt) => opt,
            Err(e) => {
                tracing::warn!(
                    address = ?change.address,
                    resource_type = %type_name,
                    error = %e,
                    "magma adopt: import-id discovery failed; cannot adopt"
                );
                None
            }
        },
        None => natural_import_id(change),
    }
}

/// The generic adoption interpreter: discover a create-conflicted resource's
/// opaque provider import id by reading the spec's list data source with a
/// filter derived from the resource config, matching the natural key, and
/// formatting the import id. Provider-agnostic — every [`crate::adopt::AdoptionSpec`]
/// drives the SAME read here; a new adoptable type is a new spec value, not a
/// branch. The data-source config is fully populated (the spec's required
/// filter fields), so it never hits the null-filter nil-deref class
/// ApplyRpcContract part 7 fixed.
async fn discover_via_spec(
    spec: &crate::adopt::AdoptionSpec,
    change: &ResourceChange,
    lp: &mut LiveProvider,
) -> Result<Option<String>, EngineError> {
    let Some(after) = change.after.as_ref() else {
        return Ok(None);
    };
    // The provider must expose the list data source to discover the id.
    let Some(ds_schema) = lp.schema.data_source(&spec.list_data_source).cloned() else {
        return Ok(None);
    };
    let filter = crate::adopt::render_filter(&spec.filter_template, after);
    let filter_dv =
        DynamicValue::from_json(&filter, &ds_schema).map_err(|e| EngineError::Cty(e.to_string()))?;
    let Some(result_dv) = lp
        .conn
        .read_data_source(&spec.list_data_source, &filter_dv)
        .await
        .map_err(|e| {
            EngineError::Rpc(
                provider_local_name(&spec.resource_type),
                format!("{} discovery: {e}", spec.list_data_source),
            )
        })?
    else {
        return Ok(None);
    };
    let result_json = result_dv
        .to_json(&ds_schema)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
    let Some(rows) = result_json.get("result").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    let matched = rows
        .iter()
        .find(|row| crate::adopt::row_matches(row, after, &spec.match_keys));
    Ok(matched.and_then(|row| crate::adopt::render_import_id(&spec.id_template, after, row)))
}

/// One state mutation a node's apply performed.
///
/// Both variants are keyed on the node's OWN address, which is unique
/// within a plan — so the deltas of two nodes in the same wave touch
/// disjoint state entries **by construction**. That disjointness is what
/// makes in-wave concurrency safe against `State`: there is no shared
/// mutable entry to race over, only a shared container whose writes are
/// replayed serially by the caller.
#[derive(Debug, Clone)]
pub(crate) enum StateOp {
    Insert {
        address: ResourceAddress,
        attrs: serde_json::Value,
        schema_version: u64,
    },
    Remove {
        address: ResourceAddress,
    },
}

/// Everything one node's apply produced besides its `AppliedChange`: the
/// state writes it wants committed, and what its wall-clock went to.
///
/// The state writes are *recorded* rather than *performed* so that
/// `apply_one` no longer needs `&mut State`, which is the single change
/// that lets a wave's nodes run concurrently. The caller replays them in
/// wave order, keeping the state-commit / cursor-record / checkpoint
/// sequence exactly as serial and as ordered as it was before.
///
/// Deltas accumulate on the **error** path too, and must: a replace that
/// destroys the old instance and then fails to create the replacement has
/// genuinely removed it, and dropping that removal would leave state
/// claiming a resource the cloud no longer has.
#[derive(Debug, Clone, Default)]
pub(crate) struct NodeRecord {
    ops: Vec<StateOp>,
    /// Time blocked in the rate limiter before this node's RPCs.
    pacer_wait_ms: u64,
    /// Time inside this node's provider RPCs, excluding pacer wait.
    rpc_ms: u64,
}

impl NodeRecord {
    fn insert(&mut self, address: &ResourceAddress, attrs: serde_json::Value, schema_version: u64) {
        self.ops.push(StateOp::Insert {
            address: address.clone(),
            attrs,
            schema_version,
        });
    }

    fn remove(&mut self, address: &ResourceAddress) {
        self.ops.push(StateOp::Remove {
            address: address.clone(),
        });
    }

    /// Replay this node's writes onto the real state, in the order they
    /// were performed. Ordering matters within a node — a replace records
    /// `Remove` then `Insert`, and swapping them would leave the resource
    /// absent.
    fn commit(&self, state: &mut State) {
        for op in &self.ops {
            match op {
                StateOp::Insert {
                    address,
                    attrs,
                    schema_version,
                } => insert_resource(state, address, attrs.clone(), *schema_version),
                StateOp::Remove { address } => remove_resource(state, address),
            }
        }
    }
}

/// Apply one change, recording its state writes and its timing into `rec`.
///
/// A thin timing wrapper over [`apply_one_inner`], which holds the real
/// logic. Splitting it this way keeps the measurement total — the inner
/// function has many early returns (per action, per RPC failure, per adopt
/// branch) and threading a stopwatch through every one of them would
/// guarantee that some future path forgets to stop the clock and silently
/// under-reports. Timing the whole call and subtracting the pacer wait the
/// inner already measured cannot miss a path.
async fn apply_one(
    change: &ResourceChange,
    rec: &mut NodeRecord,
    reg: &mut Registry<'_>,
) -> Result<AppliedChange, EngineError> {
    let started = std::time::Instant::now();
    let out = apply_one_inner(change, rec, reg).await;
    let total = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // Whatever was not spent waiting on the rate limiter was spent in (or
    // on the way to) the provider. `saturating_sub` because the two clocks
    // are read separately and could in principle disagree by a tick.
    rec.rpc_ms = total.saturating_sub(rec.pacer_wait_ms);
    out
}

async fn apply_one_inner(
    change: &ResourceChange,
    rec: &mut NodeRecord,
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
    //
    // The wait is MEASURED, not just incurred. Time spent here versus time
    // spent in the RPCs below is exactly the rate-bound-vs-latency-bound
    // question, and it is the only honest basis for deciding whether
    // raising `ApplyContext::concurrency` above 1 can help at all.
    let pacer = reg.ctx.pacer.clone();
    if let Some(p) = pacer.as_deref() {
        let waited = std::time::Instant::now();
        let _ = p.acquire().await;
        rec.pacer_wait_ms = u64::try_from(waited.elapsed().as_millis()).unwrap_or(u64::MAX);
    }

    let type_name = change.address.type_id.0.clone();
    let provider_name = provider_local_name(&type_name);
    let lp = reg.get(&provider_name).await?;
    // Clone the implied type so the immutable schema borrow ends before
    // the mutable conn RPC calls. The provider's CURRENT declared schema
    // version travels alongside it — every `insert_resource` call below
    // stamps the REAL version instead of a hardcoded 0, so the next
    // `refresh_state`/`refresh_named` cycle can tell whether a stored
    // instance needs `UpgradeResourceState` before it decodes it.
    let implied = lp
        .schema
        .resource(&type_name)
        .ok_or_else(|| EngineError::NoResourceSchema(type_name.clone(), provider_name.clone()))?
        .clone();
    let current_schema_version = lp.schema.resource_version_u64(&type_name);

    let null_json = serde_json::Value::Null;
    let prior_dv = DynamicValue::from_json(change.before.as_ref().unwrap_or(&null_json), &implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;

    match change.action {
        Action::Delete | Action::Forget => {
            let null_dv = DynamicValue::from_json(&null_json, &implied)
                .map_err(|e| EngineError::Cty(e.to_string()))?;
            if let Err(e) = rpc_retry!(pacer.as_deref(), lp
                .conn
                .apply_resource_change(&type_name, &prior_dv, &null_dv, &null_dv))
            {
                // RPC future has resolved → the mutable conn borrow is over;
                // read the crash/close signals off the same `lp` and build a
                // crash-aware error.
                let (crash, close) = provider_failure_signals(lp);
                return Err(rpc_error(
                    &provider_name,
                    "apply_resource_change",
                    crash,
                    close,
                    &e.to_string(),
                ));
            }
            rec.remove(&change.address);
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
            let planned = match rpc_retry!(pacer.as_deref(), lp.conn.plan_resource_change(
                &type_name,
                &prior_dv,
                &config_dv,
                &config_dv
            )) {
                Ok(p) => p,
                Err(e) => {
                    let (crash, close) = provider_failure_signals(lp);
                    return Err(rpc_error(
                        &provider_name,
                        "plan_resource_change",
                        crash,
                        close,
                        &e.to_string(),
                    ));
                }
            };

            // The provider's `requires_replace` — computed by the SAME RPC
            // above — is the ONLY authoritative signal for "does this
            // change need destroy+create instead of an in-place update?".
            // magma-plan's Config×State heuristic cannot know this (see
            // magma-plan's module docs): a ForceNew attribute plans as a
            // plain `Action::Update` there today. Honor the provider's
            // live signal regardless of what the plan said, AND honor an
            // already-Replace-classified change (`Action::Replace` /
            // `CreateThenDelete` / `DeleteThenCreate`, in case a future
            // schema-aware magma-plan or another Reconciler produced one)
            // so neither source can be silently ignored.
            //
            // Before this branch existed, EVERY one of these cases fell
            // through to the single `apply_resource_change` call below,
            // sending the provider a malformed request — `prior_state`
            // from the OLD instance paired with a `planned_state` the
            // provider itself computed as a REPLACEMENT (identity
            // attributes flipped unknown). The outcome was provider-
            // dependent and unverified: a hard API failure (safe but
            // confusing), or a provider that silently no-ops the
            // immutable field while updating the rest, leaving magma's
            // recorded state wrong with no error surfaced.
            let is_replace = !planned.requires_replace.is_empty()
                || matches!(
                    change.action,
                    Action::Replace | Action::CreateThenDelete | Action::DeleteThenCreate
                );
            if is_replace {
                return apply_replace(
                    change,
                    &prior_dv,
                    &config_dv,
                    &implied,
                    &type_name,
                    &provider_name,
                    lp,
                    pacer.as_deref(),
                    rec,
                    current_schema_version,
                )
                .await;
            }

            let planned_dv = planned.state;
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
                        // Resolve the import id: the natural `name` for
                        // name-keyed providers (github), or a discovered
                        // `<zone_id>/<record_id>` for opaque-id resources
                        // (cloudflare_dns_record) via the per-type resolver.
                        if let Some(id) = resolve_import_id(change, &type_name, lp).await {
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
                                // RETRY the confirming ReadResource. Every other
                                // read path uses rpc_retry!; this one didn't, so
                                // a TRANSIENT read failure (RPC hiccup, rate
                                // limit, momentary provider crash) fell straight
                                // through to `imp_dv` — the bare import STUB (id
                                // only). For a name-keyed github_repository that
                                // persists `attributes.name = null`, and every
                                // dependent `${github_repository.X.name}` then
                                // resolves to null → empty-URL 404. This is the
                                // izumi/asobi 2/831 corruption: not a legacy
                                // entry, but two adopts whose confirming read
                                // hiccupped with no retry.
                                let full_dv = match rpc_retry!(
                                    pacer.as_deref(),
                                    lp.conn.read_resource(&type_name, &imp_dv)
                                ) {
                                    Ok(Some(read_dv)) => read_dv,
                                    _ => imp_dv,
                                };
                                let mut attrs = full_dv
                                    .to_json(&implied)
                                    .map_err(|e| EngineError::Cty(e.to_string()))?;
                                // Defense-in-depth: if even the retried read
                                // couldn't confirm and we fell back to the stub,
                                // the import id IS the name for a name-keyed
                                // github_repository — backfill it so the adopted
                                // state is NEVER identity-less (computed attrs may
                                // still be incomplete; a refresh reconciles them,
                                // and the ${…name} fallback in substitute_refs
                                // covers references either way).
                                if change.address.type_id.0 == "github_repository"
                                    && attrs
                                        .get("name")
                                        .map_or(true, serde_json::Value::is_null)
                                {
                                    if let Some(o) = attrs.as_object_mut() {
                                        o.insert(
                                            "name".to_string(),
                                            serde_json::Value::String(id.clone()),
                                        );
                                    }
                                    tracing::warn!(
                                        address = ?change.address,
                                        import_id = %id,
                                        "magma apply: adopt ReadResource could not confirm a name after retry; backfilled identity from import id (computed attrs may be incomplete)"
                                    );
                                }
                                rec.insert(
                                    &change.address,
                                    attrs.clone(),
                                    current_schema_version,
                                );
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
                    // Not an adoptable conflict → a genuine apply failure.
                    // Read the crash/close signals off `lp` (the import/read
                    // RPCs above have resolved, so the conn borrow is over)
                    // so a SIGSEGV during apply becomes a typed crash, not
                    // an opaque "channel closed".
                    let (crash, close) = provider_failure_signals(lp);
                    return Err(rpc_error(
                        &provider_name,
                        "apply_resource_change",
                        crash,
                        close,
                        &msg,
                    ));
                }
            };
            let new_attrs = new_dv
                .to_json(&implied)
                .map_err(|e| EngineError::Cty(e.to_string()))?;
            rec.insert(&change.address, new_attrs.clone(), current_schema_version);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: Some(new_attrs),
            })
        }
    }
}

/// Orchestrate a change the provider requires be REPLACED (destroy then
/// create) rather than updated in place — see the `is_replace` branch in
/// [`apply_one`] for how a change lands here.
///
/// Sends the SAME two RPC pairs Terraform core issues for a replace:
///
/// 1. `ApplyResourceChange(prior_state → null)` — destroy the old
///    instance.
/// 2. A FRESH `PlanResourceChange(null → config)` — the create half's
///    planned state (defaults, computed-attribute placeholders) is
///    computed from a null prior, never reused from the pre-replace
///    plan a real provider may have shaped as a replacement (e.g. with
///    identity attributes already flipped unknown).
/// 3. `ApplyResourceChange(null → create_planned)` — create the
///    replacement.
///
/// Never the single malformed `ApplyResourceChange(prior_state,
/// replacement-shaped planned_state)` call the old catch-all sent for
/// every action alike — see [`apply_one`]'s `is_replace` doc comment for
/// why that was unsafe.
///
/// Destroy-before-create (`Action::DeleteThenCreate`) is the only order
/// magma supports today; there is no `create_before_destroy` lifecycle
/// knob yet, so `Action::CreateThenDelete` is treated identically (a
/// named simplification — matches [`crate::apply_one`]'s M0 structural
/// path, which also "ignores ordering" for these two variants).
async fn apply_replace(
    change: &ResourceChange,
    prior_dv: &DynamicValue,
    config_dv: &DynamicValue,
    implied: &magma_cty::CtyType,
    type_name: &str,
    provider_name: &str,
    lp: &mut LiveProvider,
    pacer: Option<&LeakyBucket>,
    rec: &mut NodeRecord,
    current_schema_version: u64,
) -> Result<AppliedChange, EngineError> {
    let null_dv = DynamicValue::from_json(&serde_json::Value::Null, implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;

    // 1. Destroy the prior instance.
    if let Err(e) = rpc_retry!(
        pacer,
        lp.conn
            .apply_resource_change(type_name, prior_dv, &null_dv, &null_dv)
    ) {
        let (crash, close) = provider_failure_signals(lp);
        return Err(rpc_error(
            provider_name,
            "apply_resource_change[replace:destroy]",
            crash,
            close,
            &e.to_string(),
        ));
    }
    // The destroy HAPPENED. Record it before the create half is even
    // attempted: if step 3 fails, this node returns Err, and the delta must
    // STILL carry the removal — state claiming a resource the provider just
    // destroyed is worse than either outcome alone.
    rec.remove(&change.address);

    // 2. Re-plan the create half from a clean slate.
    let create_planned = match rpc_retry!(
        pacer,
        lp.conn
            .plan_resource_change(type_name, &null_dv, config_dv, config_dv)
    ) {
        Ok(p) => p,
        Err(e) => {
            let (crash, close) = provider_failure_signals(lp);
            return Err(rpc_error(
                provider_name,
                "plan_resource_change[replace:create]",
                crash,
                close,
                &e.to_string(),
            ));
        }
    };

    // 3. Create the replacement.
    let new_dv = match rpc_retry!(
        pacer,
        lp.conn.apply_resource_change(
            type_name,
            &null_dv,
            &create_planned.state,
            config_dv
        )
    ) {
        Ok(dv) => dv,
        Err(e) => {
            let (crash, close) = provider_failure_signals(lp);
            return Err(rpc_error(
                provider_name,
                "apply_resource_change[replace:create]",
                crash,
                close,
                &e.to_string(),
            ));
        }
    };

    let new_attrs = new_dv
        .to_json(implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
    rec.insert(&change.address, new_attrs.clone(), current_schema_version);
    Ok(AppliedChange {
        address: change.address.clone(),
        // Record what ACTUALLY happened (destroy + create), not
        // whatever the incoming plan classified this as — an
        // `Action::Update`-classified change that turned out to
        // require replace must not be recorded as an in-place update.
        action: Action::DeleteThenCreate,
        before: change.before.clone(),
        after: Some(new_attrs),
    })
}

/// The provider's local name from a resource type id: the prefix before
/// the first `_` (`github_repository` → `github`, `aws_s3_bucket` →
/// `aws`). Matches `terraform-provider-<name>`.
/// The provider's local name (the `provider "<name>" {}` block name a
/// rendered config would use) inferred from a resource type's prefix —
/// `"github_repository"` → `"github"`. `pub(crate)` so
/// [`crate::import_prepass::ConfiguredImportEnvironment`] can select
/// the SAME provider a plan/apply RPC for this type would dial, without
/// a second copy of this trivial-but-load-bearing mapping.
pub(crate) fn provider_local_name(type_id: &str) -> String {
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
    // THE cloudflare_accounts ReadDataSource path: the live SIGSEGV hit
    // here. On RPC error, read the crash/close signals off `lp` (the conn
    // borrow ended when the future resolved) so a provider crash surfaces
    // as a typed `ProviderCrashed`, not the opaque "channel closed".
    let read_result = lp.conn.read_data_source(&type_name, &config_dv).await;
    let state_opt = match read_result {
        Ok(v) => v,
        Err(e) => {
            let (crash, close) = provider_failure_signals(lp);
            return Err(rpc_error(
                &provider_name,
                "read_data_source",
                crash,
                close,
                &e.to_string(),
            ));
        }
    };
    // Provider ANSWERED but with null state — not a crash, a contract
    // miss. Keep it a plain `Rpc`.
    let state_dv = state_opt.ok_or_else(|| {
        EngineError::Rpc(
            provider_name.clone(),
            format!("data source {type_name} returned null state"),
        )
    })?;
    state_dv
        .to_json(&implied)
        .map_err(|e| EngineError::Cty(e.to_string()))
}

/// Split a plan's changes into `(data sources, NoOp managed, real managed)`.
///
/// The data-kind split MUST come BEFORE the NoOp split. A data source is
/// frequently planned as `NoOp` (its config is unchanged), but its result
/// still has to be *read* (`ReadDataSource`) and folded into the resolution
/// map every apply — otherwise a managed resource's
/// `${data.<type>.<name>.<attr>}` reference leaks the literal string into the
/// provider RPC (the rio-drive grafana `zone_id =
/// ${data.cloudflare_zones.rio_zone.result[0].id}` → Cloudflare 400 7003).
/// Routing ALL data-kind changes through the read path regardless of action is
/// the terraform-correct behavior (data sources are read on every apply) and
/// makes the leaked-data-reference class unrepresentable.
///
/// The one exception — a data source planned `Delete`/`Forget` (orphaned:
/// removed from config) — is still routed here into `datas`, but the `datas`
/// loop FORGETS it (drops it from state) instead of reading it. See REACTION C
/// in `run_plan_with_providers`: a removed data source has no config left to
/// read against, so re-reading it is both meaningless and the orphan-refresh
/// crash trigger.
fn partition_changes<'a>(
    changes: &'a [ResourceChange],
) -> (
    Vec<&'a ResourceChange>,
    Vec<&'a ResourceChange>,
    Vec<&'a ResourceChange>,
) {
    let (datas, non_datas): (Vec<&ResourceChange>, Vec<&ResourceChange>) = changes
        .iter()
        .partition(|c| c.address.kind == ResourceKind::Data);
    let (noops, reals): (Vec<&ResourceChange>, Vec<&ResourceChange>) = non_datas
        .into_iter()
        .partition(|c| c.action == Action::NoOp);
    (datas, noops, reals)
}

/// Collect every `${…}` reference path (inner, no wrapper) found anywhere in
/// a config value. `pub(crate)`: `crate::dependency_ordered` (the M0
/// structural apply's own dependency-graph ordering, `lib.rs`) reuses this
/// same extraction rather than re-implementing it — one reference-scanning
/// pass, shared by both apply engines.
///
/// Escape-aware (2026-07-23): HCL2's own escaping convention doubles `$`/`%`
/// before a `{` (`$${`/`%%{`) to mean a literal `${`/`%{` that must NEVER be
/// treated as interpolation. A naive `s.find("${")` misreads a correctly
/// escaped value — e.g. `github_repository_file.content` carrying a GitHub
/// Actions `$${{ secrets.BOT_PAT }}` — as a real reference, extracting the
/// malformed path `{ secrets.BOT_PAT ` (the stray leading brace is the
/// leftover second `{` of the double-brace `${{ }}` GitHub Actions syntax).
/// Same root cause and same fix shape as `magma-test-laws`'s
/// `assert_no_dangling_references` (see that crate's `architecture.rs` for
/// the full incident writeup) — ported here because this function does its
/// OWN independent scan, not a shared one.
pub(crate) fn collect_refs(v: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => scan_refs(s, out),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// Byte-indexed, escape-aware `${…}` reference scan shared by [`collect_refs`]
/// and (via its own copy, `substitute_refs` below, since that function must
/// also rewrite `$${`/`%%{` back to `${`/`%{` in its output — a distinct job
/// from pure extraction). Walks `s` left to right; at each position prefers
/// the 3-byte escape match (`$${`/`%%{`, consumed whole, never re-examined —
/// this is what stops the trailing brace of an escaped `${{` from being
/// mistaken for a fresh opener) over the 2-byte reference-open match (`${`).
/// Slicing only ever happens immediately before/after one of `$`/`%`/`{`/`}`
/// — all single-byte ASCII, so every slice point is a guaranteed UTF-8 char
/// boundary regardless of what non-ASCII content surrounds it.
fn scan_refs(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && (bytes[i] == b'$' || bytes[i] == b'%')
            && bytes[i + 1] == bytes[i]
            && bytes[i + 2] == b'{'
        {
            i += 3;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let after = &s[i + 2..];
            if let Some(end) = after.find('}') {
                out.push(after[..end].trim().to_string());
                i += 2 + end + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
}

/// The `(type, name)` a reference path targets — `github_repository.galho.node_id`
/// → `("github_repository", "galho")`. Returns `None` for `data.*` sources
/// (resolved from existing state, not ordered as apply dependencies) or
/// malformed paths. Strips any `[index]` from the name segment.
/// `pub(crate)`: shared with `crate::dependency_ordered` (`lib.rs`) — see
/// `collect_refs`'s doc.
pub(crate) fn ref_target(inner: &str) -> Option<(String, String)> {
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

/// The resource `<name>` of a `github_repository.<name>.name` reference path
/// (inner, no `${}` wrapper). In the org-posture architecture a
/// `github_repository` resource's `name` attribute IS its resource name, so
/// this is a sound fallback when the state value is null/unresolvable — it
/// resolves `${github_repository.izumi.name}` → `izumi` syntactically. Returns
/// `None` for any other shape (`.node_id`, deeper paths, non-repo types) so the
/// fallback is scoped strictly to the one attribute where name == resource-name.
fn repo_name_ref_fallback(inner: &str) -> Option<String> {
    let mut segs = inner.split('.');
    match (segs.next(), segs.next(), segs.next(), segs.next()) {
        (Some("github_repository"), Some(name), Some("name"), None) => {
            let name = name.split('[').next().unwrap_or(name);
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => None,
    }
}

/// Replace `${type.name.attr}` references in-place against `sm`. A value that
/// is exactly one reference is replaced by the resolved value (preserving its
/// type); an interpolated string has each `${…}` substituted with the
/// resolved value stringified. Unresolvable references are left untouched
/// (the apply may then fail, surfacing the gap rather than masking it) — except
/// a null/unresolvable `${github_repository.<name>.name}`, which falls back to
/// `<name>` (see [`repo_name_ref_fallback`]).
///
/// Escape-aware (2026-07-23, same incident as [`collect_refs`]): a `$${`/`%%{`
/// sequence is HCL2's own escape for a literal `${`/`%{` and is never treated
/// as a reference. Unlike `collect_refs` (pure extraction), this function also
/// REWRITES the escape back to its unescaped form in the output — real
/// Terraform's own interpolation pass does exactly this on every string it
/// renders, escaped or not, so a value containing ONLY escaped content still
/// needs `$${` → `${` applied even though no actual reference resolution
/// happens. Skipping this would ship the literal `$${{ secrets.BOT_PAT }}`
/// (with the stray extra `$`) to whatever consumes the rendered value — for
/// `github_repository_file.content`, that means a syntactically broken
/// GitHub Actions workflow lands on GitHub, silently, since the resource
/// still creates successfully; only the workflow itself would fail at
/// GitHub's own YAML-expression-parse time, far downstream of this apply.
fn substitute_refs(v: &mut serde_json::Value, sm: &HashMap<String, serde_json::Value>) {
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if let Some(inner) = trimmed.strip_prefix("${").and_then(|x| x.strip_suffix('}')) {
                if !inner.contains("${") {
                    match resolve_reference(trimmed, sm) {
                        // A `${github_repository.<name>.name}` reference whose
                        // resolved value is NULL — a corrupt / not-yet-refreshed
                        // repo state entry (2/831 on rio carry `attributes.name =
                        // null`; the operator's `refresh` is an M0.10 no-op so it
                        // never self-heals) — would set the sub-resource's
                        // `repository` to null → `repos/<owner>//<child>` 404 →
                        // NOT `is_already_exists` → the reactive adopt-on-conflict
                        // path (natural_import_id) is never reached, so an
                        // existing GitHub label/perm can't adopt. The repo's
                        // `.name` attribute IS its resource name in the
                        // org-posture architecture, so fall back to <name>
                        // syntactically (mirrors collect_phantom_parents +
                        // natural_import_id's deref). Only `.name` refs; only on
                        // a null/unresolvable result — a genuine resolved value
                        // always wins.
                        Ok(resolved) => {
                            *v = if resolved.is_null() {
                                repo_name_ref_fallback(inner)
                                    .map_or(resolved, serde_json::Value::String)
                            } else {
                                resolved
                            };
                        }
                        Err(_) => {
                            // Unresolvable: repo-name fallback if applicable,
                            // else leave the literal untouched (surface the gap).
                            if let Some(n) = repo_name_ref_fallback(inner) {
                                *v = serde_json::Value::String(n);
                            }
                        }
                    }
                    return;
                }
            }
            if s.contains("${") || s.contains("%{") {
                let bytes = s.as_bytes();
                let mut result = String::with_capacity(s.len());
                let mut last_push = 0usize;
                let mut i = 0usize;
                while i < bytes.len() {
                    // Escaped literal: $${ or %%{ -- rewrite to the unescaped
                    // ${ or %{ (drop one $/%), never resolved as a reference.
                    if i + 2 < bytes.len()
                        && (bytes[i] == b'$' || bytes[i] == b'%')
                        && bytes[i + 1] == bytes[i]
                        && bytes[i + 2] == b'{'
                    {
                        result.push_str(&s[last_push..i]);
                        result.push(bytes[i] as char); // '$' or '%' -- single-byte ASCII, safe
                        result.push('{');
                        i += 3;
                        last_push = i;
                        continue;
                    }
                    // Genuine, unescaped interpolation open.
                    if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                        let after = &s[i + 2..];
                        if let Some(end) = after.find('}') {
                            result.push_str(&s[last_push..i]);
                            let full = &s[i..i + 2 + end + 1];
                            match resolve_reference(full, sm) {
                                Ok(serde_json::Value::String(rs)) => result.push_str(&rs),
                                Ok(other) => result.push_str(&other.to_string()),
                                Err(_) => result.push_str(full),
                            }
                            i += 2 + end + 1;
                            last_push = i;
                            continue;
                        }
                        // Unterminated `${` -- nothing left worth scanning;
                        // the trailing plain text is pushed after the loop.
                        break;
                    }
                    i += 1;
                }
                result.push_str(&s[last_push..]);
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
    fn repo_name_ref_fallback_scoped_to_dot_name() {
        assert_eq!(
            repo_name_ref_fallback("github_repository.izumi.name"),
            Some("izumi".to_string())
        );
        // strips a bracket index on the name segment
        assert_eq!(
            repo_name_ref_fallback("github_repository.izumi[0].name"),
            Some("izumi".to_string())
        );
        // NOT `.name` → no fallback (node_id ≠ resource-name)
        assert_eq!(repo_name_ref_fallback("github_repository.izumi.node_id"), None);
        // deeper path → no fallback
        assert_eq!(repo_name_ref_fallback("github_repository.izumi.name.x"), None);
        // other type → no fallback
        assert_eq!(repo_name_ref_fallback("github_branch_protection.x.name"), None);
    }

    #[test]
    fn substitute_refs_falls_back_on_null_repo_name() {
        // THE izumi residual: a corrupt/unrefreshed `github_repository` state
        // entry carries `attributes.name = null` (2/831 on rio). A sub-resource
        // `repository = ${github_repository.izumi.name}` then resolves to Null →
        // empty-repo 404 → never reaches the reactive adopt. Fall back to the
        // resource name so the create hits `.../izumi/labels` → 422 → adopt.
        let mut sm: HashMap<String, serde_json::Value> = HashMap::new();
        sm.insert(
            "github_repository".into(),
            serde_json::json!({ "izumi": { "name": serde_json::Value::Null } }),
        );
        let mut repo = serde_json::json!("${github_repository.izumi.name}");
        substitute_refs(&mut repo, &sm);
        assert_eq!(repo, serde_json::json!("izumi"));

        // A genuine resolved name always wins over the fallback.
        let mut sm2: HashMap<String, serde_json::Value> = HashMap::new();
        sm2.insert(
            "github_repository".into(),
            serde_json::json!({ "breathe": { "name": "breathe" } }),
        );
        let mut repo2 = serde_json::json!("${github_repository.breathe.name}");
        substitute_refs(&mut repo2, &sm2);
        assert_eq!(repo2, serde_json::json!("breathe"));
    }

    // ── Escape-aware collect_refs / substitute_refs (2026-07-23 incident) ──

    #[test]
    fn collect_refs_ignores_escaped_github_actions_double_brace() {
        let v = serde_json::json!(
            "name: auto-bump\njobs:\n  bump:\n    secrets:\n      BOT_PAT: $${{ secrets.BOT_PAT }}\n"
        );
        assert_eq!(collect_refs(&v), Vec::<String>::new());
    }

    #[test]
    fn collect_refs_still_finds_a_real_reference_next_to_an_escaped_one() {
        let v = serde_json::json!("$${{ secrets.BOT_PAT }} and ${github_repository.izumi.id}");
        assert_eq!(
            collect_refs(&v),
            vec!["github_repository.izumi.id".to_string()]
        );
    }

    #[test]
    fn substitute_refs_unescapes_a_pure_literal_with_no_real_reference() {
        // No entry in `sm` at all -- if this were (wrongly) treated as a
        // reference, resolution would fail; it must never even try.
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let mut content = serde_json::json!(
            "jobs:\n  bump:\n    secrets:\n      BOT_PAT: $${{ secrets.BOT_PAT }}\n"
        );
        substitute_refs(&mut content, &sm);
        assert_eq!(
            content,
            serde_json::json!("jobs:\n  bump:\n    secrets:\n      BOT_PAT: ${{ secrets.BOT_PAT }}\n")
        );
    }

    #[test]
    fn substitute_refs_unescapes_percent_brace_too() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let mut v = serde_json::json!("literal directive: %%{if true}yes%%{endif}");
        substitute_refs(&mut v, &sm);
        assert_eq!(v, serde_json::json!("literal directive: %{if true}yes%{endif}"));
    }

    #[test]
    fn substitute_refs_resolves_a_real_reference_sitting_next_to_an_escaped_literal() {
        let mut sm: HashMap<String, serde_json::Value> = HashMap::new();
        sm.insert(
            "github_repository".into(),
            serde_json::json!({ "izumi": { "id": "R_kgAizumi" } }),
        );
        let mut v = serde_json::json!("$${{ secrets.BOT_PAT }} repo=${github_repository.izumi.id}");
        substitute_refs(&mut v, &sm);
        assert_eq!(v, serde_json::json!("${{ secrets.BOT_PAT }} repo=R_kgAizumi"));
    }

    #[test]
    fn substitute_refs_does_not_corrupt_multi_byte_utf8_around_escaped_content() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let mut v = serde_json::json!("caf\u{e9} $${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}");
        substitute_refs(&mut v, &sm);
        assert_eq!(v, serde_json::json!("caf\u{e9} ${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}"));

        // A null NON-`.name` ref keeps prior behavior (replace-with-null, no fallback).
        let mut node = serde_json::json!("${github_repository.izumi.node_id}");
        let mut sm3: HashMap<String, serde_json::Value> = HashMap::new();
        sm3.insert(
            "github_repository".into(),
            serde_json::json!({ "izumi": { "node_id": serde_json::Value::Null } }),
        );
        substitute_refs(&mut node, &sm3);
        assert_eq!(node, serde_json::Value::Null);
    }

    #[test]
    fn rpc_error_folds_provider_crash_into_typed_variant() {
        // The live rio evidence: cloudflare 5.13.0 SIGSEGVs during
        // ReadDataSource. The drain captured the panic; the helper must
        // produce a TYPED `ProviderCrashed` (the operator's classifier
        // matches the variant, not a substring), carrying the panic line
        // AND the originating opaque RPC error.
        let crash = ProviderCrash {
            lines: vec![
                "panic: runtime error: invalid memory address or nil pointer dereference [signal SIGSEGV]".to_string(),
                "goroutine 17 [running]:".to_string(),
            ],
            signal: Some(11),
        };
        let err = rpc_error(
            "cloudflare",
            "read_data_source",
            Some(crash),
            Some("connection closed because of a broken pipe".to_string()),
            "Service was not ready: channel closed",
        );
        match err {
            EngineError::ProviderCrashed {
                provider,
                op,
                detail,
            } => {
                assert_eq!(provider, "cloudflare");
                assert_eq!(op, "read_data_source");
                // The panic frame is surfaced (not the goroutine line).
                assert!(detail.contains("nil pointer dereference"));
                assert!(detail.contains("[signal SIGSEGV]"));
                // The exit-signal confirmation is folded in.
                assert!(detail.contains("signal 11"));
                // The originating opaque RPC error is preserved for context.
                assert!(detail.contains("channel closed"));
            }
            other => panic!("expected ProviderCrashed, got {other:?}"),
        }
    }

    #[test]
    fn rpc_error_folds_close_reason_when_no_crash() {
        // Provider didn't crash (no captured panic) but the h2 connection
        // recorded a close reason — fold it into an enriched `Rpc` so
        // "channel closed" gains its real cause.
        let err = rpc_error(
            "github",
            "plan_resource_change",
            None,
            Some("peer closed connection without sending TLS close_notify".to_string()),
            "Service was not ready: channel closed",
        );
        match err {
            EngineError::Rpc(provider, msg) => {
                assert_eq!(provider, "github");
                assert!(msg.contains("plan_resource_change"));
                assert!(msg.contains("channel closed"));
                assert!(msg.contains("connection closed: peer closed connection"));
            }
            other => panic!("expected enriched Rpc, got {other:?}"),
        }
    }

    #[test]
    fn rpc_error_plain_when_no_crash_and_no_close_reason() {
        // No crash, no close reason → a plain `Rpc` with the op prefix.
        let err = rpc_error("aws", "configure", None, None, "invalid credentials");
        match err {
            EngineError::Rpc(provider, msg) => {
                assert_eq!(provider, "aws");
                assert_eq!(msg, "configure: invalid credentials");
            }
            other => panic!("expected plain Rpc, got {other:?}"),
        }
    }

    #[test]
    fn rpc_error_prefers_panic_line_over_first_captured_line() {
        // When the first captured line is a non-panic frame (e.g. a stray
        // "runtime error" log without "panic:"), but a later line IS the
        // panic, the helper surfaces the panic frame.
        let crash = ProviderCrash {
            lines: vec![
                "goroutine 1 [running]:".to_string(),
                "panic: send on closed channel".to_string(),
            ],
            signal: None,
        };
        let err = rpc_error("p", "apply_resource_change", Some(crash), None, "boom");
        match err {
            EngineError::ProviderCrashed { detail, .. } => {
                assert!(detail.contains("panic: send on closed channel"));
                // No signal observed → no "(signal N)" fragment.
                assert!(!detail.contains("signal "));
            }
            other => panic!("expected ProviderCrashed, got {other:?}"),
        }
    }

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

    /// COMPOSITE-KEY IMPORT IDS (2026-07-07): the github sub-resource adopt
    /// fix. Without composite ids, `github_branch_protection.akeyless_stack_main`
    /// would adopt by the WRONG id "akeyless_stack_main" (its address name) →
    /// import_resource_state fails → the create-that-exists never adopts (the
    /// pleme-io-opensource 8-stuck-creates / all-422 wedge). Name-keyed
    /// (github_repository) and non-github types are unchanged.
    #[test]
    fn natural_import_id_builds_composite_keys_for_github_sub_resources() {
        use magma_types::{ModulePath, ResourceKind, ResourceTypeId};
        let mk = |ty: &str, name: &str, after: serde_json::Value| ResourceChange {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(ty.into()),
                name: name.into(),
                key: None,
            },
            action: Action::Create,
            before: None,
            after: Some(after),
            reasons: vec![],
        };
        // Composite <parent>:<subkey>, NOT the bare address name.
        assert_eq!(
            natural_import_id(&mk(
                "github_branch_protection",
                "akeyless_stack_main",
                serde_json::json!({ "repository_id": "akeyless_stack", "pattern": "main" })
            )),
            Some("akeyless_stack:main".to_string())
        );
        assert_eq!(
            natural_import_id(&mk(
                "github_actions_secret",
                "breathe_token",
                serde_json::json!({ "repository": "breathe", "secret_name": "TOKEN" })
            )),
            Some("breathe:TOKEN".to_string())
        );
        assert_eq!(
            natural_import_id(&mk(
                "github_repository_environment",
                "breathe_prod",
                serde_json::json!({ "repository": "breathe", "environment": "prod" })
            )),
            Some("breathe:prod".to_string())
        );
        assert_eq!(
            natural_import_id(&mk(
                "github_issue_label",
                "breathe_bug",
                serde_json::json!({ "repository": "breathe", "name": "bug" })
            )),
            Some("breathe:bug".to_string())
        );
        // Repo-scoped singleton imports by the parent repo name.
        assert_eq!(
            natural_import_id(&mk(
                "github_repository_topics",
                "breathe",
                serde_json::json!({ "repository": "breathe", "topics": ["rust"] })
            )),
            Some("breathe".to_string())
        );
        // Name-keyed github_repository unchanged: the id IS the name.
        assert_eq!(
            natural_import_id(&mk(
                "github_repository",
                "breathe",
                serde_json::json!({ "name": "breathe" })
            )),
            Some("breathe".to_string())
        );
        // A composite type missing a key falls back to name/address-name (no panic).
        assert_eq!(
            natural_import_id(&mk(
                "github_actions_secret",
                "orphan",
                serde_json::json!({ "repository": "breathe" })
            )),
            Some("orphan".to_string())
        );
        // THE izumi/asobi residual: a sub-resource's `repository` is authored as
        // an UNRESOLVED `${github_repository.<name>.name}` reference in plan
        // `after` (substitution runs later, in the create path). The import id
        // must still resolve to `<name>:<subkey>` STATE-INDEPENDENTLY, so the
        // existing GitHub labels adopt instead of failing `${…}:bug` import →
        // empty-repo-404 create → parent-phantom-drop loop.
        assert_eq!(
            natural_import_id(&mk(
                "github_issue_label",
                "izumi_label_bug",
                serde_json::json!({ "repository": "${github_repository.izumi.name}", "name": "bug" })
            )),
            Some("izumi:bug".to_string())
        );
        // actions_repository_permissions imports by the (deref'd) parent repo name.
        assert_eq!(
            natural_import_id(&mk(
                "github_actions_repository_permissions",
                "asobi_actions",
                serde_json::json!({ "repository": "${github_repository.asobi.name}" })
            )),
            Some("asobi".to_string())
        );
        // A repo-scoped singleton with an unresolved ref derefs too.
        assert_eq!(
            natural_import_id(&mk(
                "github_repository_topics",
                "izumi",
                serde_json::json!({ "repository": "${github_repository.izumi.name}", "topics": ["rust"] })
            )),
            Some("izumi".to_string())
        );
        // BOUNDARY: branch_protection's `repository_id` is a `${…node_id}`
        // reference whose value is NOT the resource name — it must stay raw
        // (deref'ing to the name would be wrong). Documents the intentional
        // scope: only `.name` references deref.
        assert_eq!(
            natural_import_id(&mk(
                "github_branch_protection",
                "izumi_main",
                serde_json::json!({ "repository_id": "${github_repository.izumi.node_id}", "pattern": "main" })
            )),
            Some("${github_repository.izumi.node_id}:main".to_string())
        );
    }

    #[test]
    fn noop_data_source_routes_to_read_path_not_noops() {
        use magma_types::{ModulePath, ResourceKind, ResourceTypeId};
        // The rio-drive grafana regression: a data source planned as NoOp (its
        // config unchanged) must still be ROUTED THROUGH THE READ PATH so its
        // result lands in the resolution map. Before the fix it fell into the
        // `noops` bucket (action == NoOp swept first) and was never read, so a
        // dependent managed Create leaked `${data.*}` verbatim → Cloudflare 400.
        let mk = |kind, ty: &str, name: &str, action| ResourceChange {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind,
                type_id: ResourceTypeId(ty.into()),
                name: name.into(),
                key: None,
            },
            action,
            before: None,
            after: None,
            reasons: vec![],
        };
        let changes = vec![
            // a data source the planner marked NoOp (the bug trigger)
            mk(ResourceKind::Data, "cloudflare_zones", "rio_zone", Action::NoOp),
            // the dependent managed create (grafana CNAME)
            mk(ResourceKind::Managed, "cloudflare_dns_record", "grafana", Action::Create),
            // an unrelated NoOp managed resource (must stay in noops)
            mk(ResourceKind::Managed, "cloudflare_dns_record", "auth", Action::NoOp),
        ];
        let (datas, noops, reals) = partition_changes(&changes);
        // The NoOp data source is in `datas` (read path), NOT `noops`.
        assert_eq!(datas.len(), 1);
        assert_eq!(datas[0].address.type_id.0, "cloudflare_zones");
        assert!(datas.iter().all(|c| c.address.kind == ResourceKind::Data));
        // NoOp managed stays in noops; the data source is absent from it.
        assert_eq!(noops.len(), 1);
        assert_eq!(noops[0].address.name, "auth");
        assert!(noops.iter().all(|c| c.address.kind != ResourceKind::Data));
        // The real create is routed for dependency-ordered apply.
        assert_eq!(reals.len(), 1);
        assert_eq!(reals[0].address.name, "grafana");
    }

    /// The cloudflare 5.13.0 SIGSEGV root cause: a NoOp data source whose
    /// value is already resolved in `before` must be carried forward, NOT
    /// re-read. Re-reading sends the provider the plan's null `after` config
    /// (null `name` filter) and the provider nil-derefs. Proof: a plan with
    /// ONLY a resolved NoOp data source applies cleanly with NO provider
    /// reachable (empty workspace, no `$MAGMA_PROVIDER_DIR`) — if the engine
    /// tried to re-read it, the spawn would fail and it'd land in `failed`.
    #[tokio::test]
    async fn noop_data_source_with_before_is_carried_forward_without_a_read() {
        use magma_types::{ModulePath, PlanId, ResourceAddress, ResourceTypeId};
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };

        let resolved = serde_json::json!({
            "name": "quero.cloud",
            "result": [{ "id": "zone-abc", "name": "quero.cloud" }],
        });
        let plan = Plan {
            id: PlanId([0u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::from("/ws"),
            variables: Default::default(),
            resource_changes: vec![ResourceChange {
                address: ResourceAddress {
                    module: ModulePath::root(),
                    kind: ResourceKind::Data,
                    type_id: ResourceTypeId("cloudflare_zones".into()),
                    name: "rio_zone".into(),
                    key: None,
                },
                action: Action::NoOp,
                before: Some(resolved.clone()),
                after: None, // exactly the live plan shape that triggered the bug
                reasons: vec![],
            }],
            output_changes: vec![],
            observation: magma_types::Observation::unrefreshed(),
        };
        let mut state = State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![],
        };
        let td = tempfile::tempdir().unwrap();
        let ctx = ApplyContext::new(td.path().to_path_buf());

        let outcome = run_plan_with_providers(&plan, &mut state, &ctx).await;

        assert!(
            outcome.failed.is_empty(),
            "a resolved NoOp data source must not be re-read (would spawn a \
             provider that isn't there): {:?}",
            outcome.failed
        );
        assert_eq!(outcome.applied.len(), 1, "the data source carried forward");
        let a = &outcome.applied[0];
        assert_eq!(a.address.type_id.0, "cloudflare_zones");
        assert_eq!(
            a.after.as_ref().and_then(|v| v["result"][0]["id"].as_str()),
            Some("zone-abc"),
            "the resolved `before` value is what's carried forward",
        );
    }

    /// REACTION C — the orphaned-data-source refresh crash is UNREPRESENTABLE.
    ///
    /// An orphaned data source (in state from a prior apply, now ABSENT from
    /// config → planned `Delete`) must be FORGOTTEN from state WITHOUT any
    /// provider `read_data_source` RPC. Before the reaction it fell through the
    /// `datas` loop to `read_data_source_one` with a null config; the live
    /// cloudflare 5.19.1 provider nil-derefs on the accounts/zones LIST data
    /// sources, the provider PROCESS dies, and the whole cycle cascade-fails
    /// "channel closed" (the wedge that required a manual Postgres `UPDATE` to
    /// purge the orphan rows).
    ///
    /// Proof harness (mirrors `noop_data_source_with_before_is_carried_forward…`):
    /// NO provider is reachable (empty workspace, no `$MAGMA_PROVIDER_DIR`). If
    /// the engine tried to read the orphan, `read_data_source_one` would fail to
    /// spawn the provider and the change would land in `failed`. It must instead
    /// apply cleanly (the forget path) AND the orphan must be gone from state.
    #[tokio::test]
    async fn orphaned_data_source_is_forgotten_without_a_provider_read() {
        use magma_types::{
            InstanceStatus, ModulePath, PlanId, ProviderReference, ResourceAddress, ResourceKind,
            ResourceTypeId, StateInstance, StateResource,
        };
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };

        let orphan = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Data,
            type_id: ResourceTypeId("cloudflare_accounts".into()),
            name: "current".into(),
            key: None,
        };
        // Exactly the live orphan shape: in state/`before`, absent from config
        // (`after: None`), so the planner emits `Delete`.
        let plan = Plan {
            id: PlanId([0u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::from("/ws"),
            variables: Default::default(),
            resource_changes: vec![ResourceChange {
                address: orphan.clone(),
                action: Action::Delete,
                before: Some(serde_json::json!({ "result": [{ "id": "acct-1" }] })),
                after: None,
                reasons: vec![magma_types::ChangeReason::DeletedResource],
            }],
            output_changes: vec![],
            observation: magma_types::Observation::unrefreshed(),
        };
        // State starts holding the orphaned data-source row (a prior apply put
        // it there); the reaction must purge it.
        let mut state = State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![StateResource {
                address: orphan.clone(),
                provider: ProviderReference {
                    source: "cloudflare/cloudflare".into(),
                    name: "cloudflare".into(),
                    alias: None,
                },
                instances: vec![StateInstance {
                    index_key: None,
                    schema_version: 0,
                    attributes: serde_json::json!({ "result": [{ "id": "acct-1" }] }),
                    sensitive_attribute_paths: Vec::new(),
                    private: vec![],
                    dependencies: vec![],
                    status: InstanceStatus::Ready,
                }],
            }],
        };

        let td = tempfile::tempdir().unwrap();
        let ctx = ApplyContext::new(td.path().to_path_buf());

        let outcome = run_plan_with_providers(&plan, &mut state, &ctx).await;

        // NO read RPC was attempted: had the engine tried, the (absent)
        // provider spawn would fail and the change would be in `failed`.
        assert!(
            outcome.failed.is_empty(),
            "an orphaned data source must be forgotten, never re-read (a read \
             would spawn a provider that isn't there): {:?}",
            outcome.failed
        );
        // The forget path emitted a clean Delete AppliedChange.
        assert_eq!(outcome.applied.len(), 1, "the orphan was forgotten");
        let a = &outcome.applied[0];
        assert_eq!(a.address, orphan);
        assert_eq!(a.action, Action::Delete);
        assert!(a.after.is_none(), "a forgotten data source has no after-state");
        // And it is gone from state — the manual Postgres purge is now automatic.
        assert!(
            state.resources.iter().all(|r| r.address != orphan),
            "the orphaned data-source row must be dropped from state",
        );
        assert!(state.resources.is_empty(), "no rows remain");
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
                    index_key: None,
                    schema_version: 0,
                    attributes: serde_json::json!({"name": "keep_me"}),
                    sensitive_attribute_paths: Vec::new(),
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

    /// `ctx = None` must be a pure pass-through to `magma_plan::plan` — the
    /// exact pre-fix behavior every caller that hasn't opted into refresh
    /// (e.g. `--refresh false`) still gets. No refresh runs, `report` is
    /// `None`, and the plan is byte-identical to calling `magma_plan::plan`
    /// directly.
    #[tokio::test]
    async fn refresh_then_plan_skips_refresh_when_ctx_is_none() {
        let cfg = magma_config::Config::from_json(serde_json::json!({
            "resource": { "github_repository": { "keep_me": { "name": "keep_me" } } }
        }))
        .unwrap();
        let mut state = State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![],
        };

        let direct = magma_plan::plan(&cfg, &state).unwrap();
        let (via_helper, report) = refresh_then_plan(&cfg, &mut state, None).await.unwrap();

        assert!(report.is_none(), "ctx = None must not produce a refresh report");
        assert_eq!(
            via_helper.resource_changes.len(),
            direct.resource_changes.len()
        );
        assert_eq!(
            via_helper.resource_changes[0].action,
            direct.resource_changes[0].action,
            "identical plan to calling magma_plan::plan directly",
        );
    }

    /// `ctx = Some(_)` against an unreachable provider must still RUN
    /// refresh (proving `refresh_then_plan` actually calls [`refresh_state`]
    /// rather than silently skipping it) while degrading safely — the same
    /// never-drop-on-uncertainty guarantee [`refresh_never_drops_when_provider_unavailable`]
    /// proves for `refresh_state` directly.
    #[tokio::test]
    async fn refresh_then_plan_runs_refresh_when_ctx_is_some() {
        use magma_types::{
            InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind,
            ResourceTypeId, StateInstance, StateResource,
        };
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };

        let cfg = magma_config::Config::from_json(serde_json::json!({
            "resource": { "github_repository": { "keep_me": { "name": "keep_me" } } }
        }))
        .unwrap();
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
                    index_key: None,
                    schema_version: 0,
                    attributes: serde_json::json!({"name": "keep_me"}),
                    sensitive_attribute_paths: Vec::new(),
                    private: vec![],
                    dependencies: vec![],
                    status: InstanceStatus::Ready,
                }],
            }],
        };

        let td = tempfile::tempdir().unwrap();
        let ctx = ApplyContext::new(td.path().to_path_buf());
        let (plan, report) = refresh_then_plan(&cfg, &mut state, Some(&ctx)).await.unwrap();

        let report = report.expect("ctx = Some(_) must produce a refresh report");
        assert_eq!(report.kept_on_error, 1, "no provider reachable — kept, not dropped");
        assert_eq!(report.dropped_instances, 0);
        assert_eq!(state.resources.len(), 1, "state untouched on uncertainty");
        assert_eq!(
            plan.resource_changes[0].action,
            Action::NoOp,
            "config matches unchanged state — still a NoOp",
        );
    }

    #[test]
    fn a_422_already_exists_must_not_evict_its_parent_repo() {
        use magma_types::{ModulePath, ResourceAddress, ResourceKind, ResourceTypeId};
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

        // A label that ALREADY EXISTS 422s, and its error text carries the very
        // same /repos/<owner>/<repo>/<child> path as a genuine parent 404. Read
        // as a phantom, this evicted 11 live repositories per failed apply on
        // pleme-io-opensource (state 2722 -> 2711) and the loop never converged.
        let already_exists = mkfail(
            "github_issue_label",
            "banken-label-bug",
            "422 Validation Failed: POST https://api.github.com/repos/pleme-io/banken/labels — already_exists",
        );
        assert!(
            collect_phantom_parents(&[already_exists]).is_empty(),
            "a 422 already-exists must NOT nominate its parent repo as a phantom"
        );

        // The genuine case still works: a real 404 on a child path.
        let genuine_404 = mkfail(
            "github_issue_label",
            "ghost-label-bug",
            "404 Not Found: POST https://api.github.com/repos/pleme-io/ghost/labels",
        );
        let got = collect_phantom_parents(&[genuine_404]);
        assert!(got.contains("ghost"), "a real 404 must still nominate the parent, got {got:?}");
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
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({ "name": attr }),
                sensitive_attribute_paths: Vec::new(),
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

    // ── Bounded, resumable cycles ──────────────────────────────────
    //
    // These reuse this file's established provider-free harness: with no
    // reachable provider, ANY change the engine actually attempts lands in
    // `failed`. That turns "was this executed?" into a directly observable
    // fact, which is exactly what the resumption invariants need to be proved
    // rather than asserted. It also means no test here can produce a
    // *successful* real change — so what is proved below is the cycle
    // machinery (what gets attempted, what gets skipped, which arm is
    // returned), not provider behaviour.

    fn repo_addr(name: &str) -> ResourceAddress {
        use magma_types::{ModulePath, ResourceTypeId};
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("github_repository".into()),
            name: name.into(),
            key: None,
        }
    }

    /// The plan's change for `name`. A cursor records changes, not addresses,
    /// so tests must hand it the same value the engine would.
    fn change_in<'a>(plan: &'a Plan, name: &str) -> &'a ResourceChange {
        plan.resource_changes
            .iter()
            .find(|c| c.address.name == name)
            .expect("change present in plan")
    }

    /// A plan of independent `Create`s — no references, so the graph is one
    /// wave and ordering plays no part in what these tests measure.
    fn plan_of_creates(names: &[&str]) -> Plan {
        Plan {
            id: magma_types::PlanId([9u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::from("/ws"),
            variables: Default::default(),
            resource_changes: names
                .iter()
                .map(|n| ResourceChange {
                    address: repo_addr(n),
                    action: Action::Create,
                    before: None,
                    after: Some(serde_json::json!({ "name": n })),
                    reasons: vec![],
                })
                .collect(),
            output_changes: vec![],
            observation: magma_types::Observation::unrefreshed(),
        }
    }

    fn empty_state() -> State {
        State {
            version: 4,
            terraform_version: "1.9.0".into(),
            serial: 1,
            lineage: uuid::Uuid::nil(),
            outputs: Default::default(),
            resources: vec![],
        }
    }

    /// Unreachable-provider context with pacing OFF — the 1 req/s pacer would
    /// add seconds of latency and confound the quantum assertions below.
    fn unpaced_ctx(dir: &std::path::Path) -> ApplyContext {
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };
        let mut ctx = ApplyContext::new(dir.to_path_buf());
        ctx.pacer = None;
        ctx
    }

    /// The delta a node records is replayed onto state verbatim, in order.
    ///
    /// Order within a node is load-bearing: a replace records `Remove` then
    /// `Insert`, and committing them the other way round would leave the
    /// resource absent from state while it exists in the cloud.
    #[test]
    fn a_node_record_commits_its_writes_in_the_order_they_happened() {
        let addr = repo_addr("r");
        let mut rec = NodeRecord::default();
        rec.remove(&addr);
        rec.insert(&addr, serde_json::json!({ "name": "r" }), 3);

        let mut state = empty_state();
        rec.commit(&mut state);

        let stored = state
            .resources
            .iter()
            .find(|r| r.address.name == addr.name)
            .expect("replace leaves the resource present, not removed");
        assert_eq!(
            stored.instances[0].schema_version, 3,
            "the provider's real schema version must survive the delta round-trip"
        );

        // And the reverse order really would lose it — which is why `commit`
        // replays rather than folding into a set.
        let mut backwards = NodeRecord::default();
        backwards.insert(&addr, serde_json::json!({ "name": "r" }), 3);
        backwards.remove(&addr);
        let mut state2 = empty_state();
        backwards.commit(&mut state2);
        assert!(
            state2.resources.iter().all(|r| r.address.name != addr.name),
            "ordering is not incidental — reversing it changes the outcome"
        );
    }

    /// An empty record is a no-op, so the NoOp fold cannot perturb state.
    #[test]
    fn an_empty_node_record_leaves_state_untouched() {
        let mut state = empty_state();
        let before = serde_json::to_string(&state).unwrap();
        NodeRecord::default().commit(&mut state);
        assert_eq!(before, serde_json::to_string(&state).unwrap());
    }

    /// The state writes of two nodes in one wave are disjoint.
    ///
    /// This is the property that would make in-wave concurrency safe against
    /// `State`: every op a node records is keyed on that node's OWN address,
    /// and addresses are unique within a plan, so two nodes can never contend
    /// for the same entry. Asserted here rather than assumed, because it is
    /// the precondition any future concurrent executor inherits.
    #[test]
    fn two_nodes_in_a_wave_record_disjoint_state_writes() {
        let a = repo_addr("a");
        let b = repo_addr("b");
        let mut ra = NodeRecord::default();
        ra.insert(&a, serde_json::json!({ "name": "a" }), 0);
        let mut rb = NodeRecord::default();
        rb.insert(&b, serde_json::json!({ "name": "b" }), 0);

        let touched = |r: &NodeRecord| -> Vec<String> {
            r.ops
                .iter()
                .map(|op| match op {
                    StateOp::Insert { address, .. } | StateOp::Remove { address } => {
                        address.name.clone()
                    }
                })
                .collect()
        };
        let ta = touched(&ra);
        let tb = touched(&rb);
        assert!(
            ta.iter().all(|x| !tb.contains(x)),
            "nodes in one wave must touch disjoint state entries; got {ta:?} vs {tb:?}"
        );

        // Committing in either order yields the same state — the definition
        // of disjointness for this purpose.
        let (mut s1, mut s2) = (empty_state(), empty_state());
        ra.commit(&mut s1);
        rb.commit(&mut s1);
        rb.commit(&mut s2);
        ra.commit(&mut s2);
        let mut n1: Vec<_> = s1.resources.iter().map(|r| r.address.name.clone()).collect();
        let mut n2: Vec<_> = s2.resources.iter().map(|r| r.address.name.clone()).collect();
        n1.sort();
        n2.sort();
        assert_eq!(n1, n2, "commit order must not change the resulting state");
    }

    /// The cycle receipt carries the rate-bound-vs-latency-bound split.
    ///
    /// Without these two numbers, "should we add workers?" can only be
    /// answered by intuition. With them it is arithmetic: a cycle whose wall
    /// clock is dominated by `pacer_wait_ms_total` cannot be sped up by any
    /// number of workers drawing on the same bucket.
    #[tokio::test]
    async fn the_receipt_reports_where_a_node_s_wall_clock_went() {
        let plan = plan_of_creates(&["a", "b"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());
        let mut state = empty_state();

        let out =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;
        let stats = out.stats();

        assert_eq!(stats.nodes_attempted, 2);
        // Pacing is off in this harness, so the wait must be zero — proving
        // the counter tracks the pacer rather than incidentally accumulating
        // elapsed time.
        assert_eq!(
            stats.pacer_wait_ms_total, 0,
            "an unpaced context must report zero rate-limiter wait"
        );
        // Every attempted node contributes to the max, even a failing one:
        // the providers are unreachable here, and that failure still costs
        // real time that an operator needs to see.
        assert!(
            stats.node_rpc_ms_max <= stats.node_rpc_ms_total,
            "max ({}) cannot exceed total ({})",
            stats.node_rpc_ms_max,
            stats.node_rpc_ms_total
        );
    }

    /// The receipt reports the structural concurrency ceiling.
    ///
    /// `max_wave_width` is what the old `waves().flatten()` destroyed. A plan
    /// of independent creates is one wide wave; reporting its width is how an
    /// operator learns whether concurrency has any room to work with at all —
    /// separately from whether the pacer would let it.
    #[tokio::test]
    async fn the_receipt_reports_the_widest_wave() {
        let plan = plan_of_creates(&["a", "b", "c", "d"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());
        let mut state = empty_state();

        let out =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;
        let stats = out.stats();

        assert_eq!(
            stats.max_wave_width, 4,
            "four independent creates are mutually concurrent — one wave of width 4"
        );
        assert_eq!(
            stats.waves_entered, 1,
            "and they form exactly one dependency wave"
        );
    }

    /// I2 — a resumed cycle re-executes NO completed node.
    ///
    /// This is the invariant that makes chunking safe rather than an infinite
    /// retry: without it, resumption would re-attempt (and for a real provider,
    /// re-CREATE) work an earlier cycle already did. The proof is structural,
    /// not statistical — a completed address is never added to the graph, so it
    /// is in no wave and no `by_key` lookup. With no provider reachable, an
    /// executed change necessarily lands in `failed`; the completed one must
    /// appear in neither `failed` nor the attempt count.
    #[tokio::test]
    async fn a_resumed_cycle_never_re_executes_a_completed_node() {
        let plan = plan_of_creates(&["a", "b", "c"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());

        // Baseline: nothing completed, so all three are attempted.
        let mut state = empty_state();
        let fresh =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;
        assert_eq!(
            fresh.stats().nodes_attempted,
            3,
            "a fresh cycle attempts every real change"
        );

        // Now resume with `b` already applied.
        let mut cursor = ApplyCursor::empty(plan.id);
        cursor.complete(change_in(&plan, "b"));
        let mut state = empty_state();
        let resumed = run_plan_with_providers_resumable(
            &plan,
            &mut state,
            &ctx,
            Some(cursor.resume(&plan).expect("cursor is for this plan")),
            None,
            None,
        )
        .await;

        assert_eq!(
            resumed.stats().nodes_attempted,
            2,
            "the completed node must not be attempted again"
        );
        let touched: Vec<&str> = resumed
            .outcome()
            .failed
            .iter()
            .map(|f| f.address.name.as_str())
            .collect();
        assert!(
            !touched.contains(&"b"),
            "a completed node must have no code path to execution, got {touched:?}"
        );
        assert_eq!(touched.len(), 2, "the other two are still attempted");
    }

    /// I1 — the convergence endpoint. Once the cursor covers every real change
    /// the cycle reports `Completed` having attempted nothing, which is what
    /// "N cycles converge for any N" bottoms out in.
    #[tokio::test]
    async fn a_cursor_covering_every_change_completes_without_attempting_anything() {
        let plan = plan_of_creates(&["a", "b", "c"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());

        let mut cursor = ApplyCursor::empty(plan.id);
        for n in ["a", "b", "c"] {
            cursor.complete(change_in(&plan, n));
        }
        let mut state = empty_state();
        let out = run_plan_with_providers_resumable(
            &plan,
            &mut state,
            &ctx,
            Some(cursor.resume(&plan).expect("cursor is for this plan")),
            None,
            None,
        )
        .await;

        assert!(out.is_complete(), "a fully-covered plan is finished: {out:?}");
        assert!(!out.needs_another_cycle());
        assert_eq!(out.stats().nodes_attempted, 0);
        assert_eq!(out.stats().nodes_remaining, 0);
        assert!(
            out.outcome().failed.is_empty(),
            "nothing was executed, so nothing can have failed"
        );
        assert!(out.cursor().is_none(), "a finished plan carries no position");
    }

    /// Zero-regression: the run-to-completion wrapper is exactly the resumable
    /// engine with no cursor and no quantum. Existing callers see no change.
    #[tokio::test]
    async fn the_wrapper_matches_the_resumable_engine_with_no_cursor_or_quantum() {
        let plan = plan_of_creates(&["a", "b"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());

        let mut s1 = empty_state();
        let via_wrapper = run_plan_with_providers(&plan, &mut s1, &ctx).await;

        let mut s2 = empty_state();
        let via_resumable =
            run_plan_with_providers_resumable(&plan, &mut s2, &ctx, None, None, None)
                .await
                .into_outcome();

        assert_eq!(via_wrapper.applied.len(), via_resumable.applied.len());
        assert_eq!(via_wrapper.failed.len(), via_resumable.failed.len());
        let names = |o: &ApplyOutcome| -> Vec<String> {
            o.failed.iter().map(|f| f.address.name.clone()).collect()
        };
        assert_eq!(names(&via_wrapper), names(&via_resumable));
        assert_eq!(s1.serial, s2.serial, "identical state effect");
    }

    /// The quantum is honoured, and — the load-bearing half — a cycle that
    /// advanced NOTHING is reported as `Stalled`, never dressed up as a yield.
    /// That is the seal on naive chunking's real failure mode: a fixed prologue
    /// bigger than the quantum, retrying forever with epsilon progress.
    #[tokio::test]
    async fn an_exhausted_quantum_with_no_progress_stalls_rather_than_yielding() {
        let plan = plan_of_creates(&["a", "b", "c"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());
        let mut state = empty_state();

        let out = run_plan_with_providers_resumable(
            &plan,
            &mut state,
            &ctx,
            None,
            Quantum::new(std::time::Duration::from_nanos(1)),
            None,
        )
        .await;

        assert_eq!(
            out.stats().nodes_attempted,
            0,
            "an already-expired quantum must stop before the first node"
        );
        assert!(
            matches!(out, CycleOutcome::Stalled { .. }),
            "no durable progress must surface as Stalled, got {out:?}"
        );
        assert!(
            out.cursor().is_some(),
            "even a stall carries the position — there is no arm without one"
        );
        assert_eq!(out.stats().nodes_remaining, 3);
    }

    /// The prologue-collapse mechanism. Deferred data-source reads are paced
    /// and are NOT persisted in `State`, so without the cursor cache every
    /// resumed cycle would re-pay the whole read prologue before reaching any
    /// new work. A cached read must be served without touching the provider —
    /// proved here by the fact that no provider exists to touch.
    #[tokio::test]
    async fn a_cached_data_read_is_served_from_the_cursor_without_a_provider() {
        use magma_types::{ModulePath, ResourceTypeId};
        let cached = serde_json::json!({ "result": [{ "id": "zone-abc" }] });
        let data_addr = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Data,
            type_id: ResourceTypeId("cloudflare_zones".into()),
            name: "rio_zone".into(),
            key: None,
        };
        let plan = Plan {
            id: magma_types::PlanId([11u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::from("/ws"),
            variables: Default::default(),
            resource_changes: vec![ResourceChange {
                address: data_addr.clone(),
                action: Action::Create,
                before: None,
                after: Some(serde_json::json!({ "name": "quero.cloud" })),
                reasons: vec![],
            }],
            output_changes: vec![],
            observation: magma_types::Observation::unrefreshed(),
        };
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());

        // Without the cache this read would be attempted and fail (no provider).
        let mut state = empty_state();
        let cold =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;
        assert_eq!(
            cold.outcome().failed.len(),
            1,
            "control: an uncached deferred read really does hit the provider"
        );
        assert_eq!(cold.stats().data_reads_performed, 1);

        // With it cached, the same cycle needs no provider at all.
        let mut cursor = ApplyCursor::empty(plan.id);
        cursor.record_data(data_addr.clone(), cached.clone());
        let mut state = empty_state();
        let warm = run_plan_with_providers_resumable(
            &plan,
            &mut state,
            &ctx,
            Some(cursor.resume(&plan).expect("cursor is for this plan")),
            None,
            None,
        )
        .await;

        assert!(
            warm.outcome().failed.is_empty(),
            "a cached read must not reach the provider: {:?}",
            warm.outcome().failed
        );
        assert_eq!(warm.stats().data_reads_cached, 1);
        assert_eq!(warm.stats().data_reads_performed, 0);
        assert_eq!(
            warm.outcome().applied[0].after.as_ref(),
            Some(&cached),
            "the cached value is what feeds dependents' references"
        );
    }

    // ── Durable per-node progress ──────────────────────────────────
    //
    // Scope note, stated up front so these are not read as more than they are:
    // `Registry` spawns real provider subprocesses and has no injection seam,
    // so no unit test can drive a *successful* managed apply through the
    // engine's main loop. The per-node call sites are therefore proved at the
    // `record_change` / `record_data_read` level — which is exactly why the
    // ordering lives in named functions rather than inline at the call site —
    // and the engine-level tests below prove what the provider-free harness
    // genuinely can: which changes get attempted, and that nothing is
    // checkpointed speculatively.

    /// A sink that fails every write, for proving the stop-on-failure rule.
    #[derive(Default)]
    struct BrokenCheckpointSink {
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CheckpointSink for BrokenCheckpointSink {
        async fn checkpoint(
            &self,
            _state: &State,
            _cursor: &ApplyCursor,
        ) -> Result<(), crate::checkpoint::CheckpointError> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::checkpoint::CheckpointError::new("store unavailable"))
        }
    }

    /// I2 — the ordering invariant. The sink must never observe a position
    /// that omits work already reflected in `state`; the cursor is advanced
    /// first, so by the time the sink is called it already covers the change.
    #[tokio::test]
    async fn a_checkpoint_sees_a_cursor_that_already_covers_the_applied_change() {
        let plan = plan_of_creates(&["a"]);
        let change = change_in(&plan, "a");
        let sink = crate::checkpoint::MemoryCheckpointSink::new();
        let mut cursor = ApplyCursor::empty(plan.id);
        let mut stats = CycleStats::default();
        let state = empty_state();

        let r = record_change(&mut cursor, change, &state, Some(&sink), &mut stats).await;

        assert_eq!(r, Recorded::Durable);
        assert_eq!(sink.writes(), 1, "one applied node, one checkpoint");
        let (_, persisted) = sink.last().await.expect("a pair was recorded");
        assert!(
            persisted.covers(change),
            "the persisted cursor must already cover the change whose effect \
             state carries — otherwise a resume would re-attempt it"
        );
        assert_eq!(stats.checkpoints_written, 1);
        assert_eq!(stats.checkpoint_failures, 0);
    }

    /// Idempotence: re-recording a change neither advances nor writes. Without
    /// this, a retried cycle would spend a store round-trip per already-known
    /// node and inflate the progress witness with work it did not do.
    #[tokio::test]
    async fn re_recording_a_known_change_writes_nothing() {
        let plan = plan_of_creates(&["a"]);
        let change = change_in(&plan, "a");
        let sink = crate::checkpoint::MemoryCheckpointSink::new();
        let mut cursor = ApplyCursor::empty(plan.id);
        let mut stats = CycleStats::default();
        let state = empty_state();

        record_change(&mut cursor, change, &state, Some(&sink), &mut stats).await;
        let again = record_change(&mut cursor, change, &state, Some(&sink), &mut stats).await;

        assert_eq!(again, Recorded::AlreadyPresent);
        assert!(!again.advanced(), "a no-op must not count as progress");
        assert_eq!(sink.writes(), 1, "still just the one write");
    }

    /// A failed checkpoint is reported as `Undurable` — advanced in memory,
    /// not on the store — so the caller stops instead of widening the gap
    /// between what the cursor claims and what survives a crash.
    #[tokio::test]
    async fn a_failed_checkpoint_is_undurable_but_still_counts_as_progress() {
        let plan = plan_of_creates(&["a"]);
        let change = change_in(&plan, "a");
        let sink = BrokenCheckpointSink::default();
        let mut cursor = ApplyCursor::empty(plan.id);
        let mut stats = CycleStats::default();
        let state = empty_state();

        let r = record_change(&mut cursor, change, &state, Some(&sink), &mut stats).await;

        assert_eq!(r, Recorded::Undurable, "the caller must be told to stop");
        assert!(
            r.advanced(),
            "the node WAS applied — reporting it as no-progress would turn a \
             real advance into a spurious stall"
        );
        assert!(cursor.covers(change), "the in-memory position still moved");
        assert_eq!(stats.checkpoint_failures, 1);
        assert_eq!(stats.checkpoints_written, 0);
    }

    /// A deferred read follows the same rule — it costs a paced token, so it
    /// is worth persisting even though it changes no state.
    #[tokio::test]
    async fn a_data_read_is_checkpointed_with_the_position_that_includes_it() {
        use magma_types::{ModulePath, ResourceTypeId};
        let addr = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Data,
            type_id: ResourceTypeId("cloudflare_zones".into()),
            name: "z".into(),
            key: None,
        };
        let value = serde_json::json!({ "result": [{ "id": "zone-abc" }] });
        let sink = crate::checkpoint::MemoryCheckpointSink::new();
        let mut cursor = ApplyCursor::empty(magma_types::PlanId([5u8; 32]));
        let mut stats = CycleStats::default();
        let state = empty_state();

        let r =
            record_data_read(&mut cursor, &addr, &value, &state, Some(&sink), &mut stats).await;

        assert_eq!(r, Recorded::Durable);
        let (_, persisted) = sink.last().await.expect("a pair was recorded");
        assert_eq!(
            persisted.data_result(&addr),
            Some(&value),
            "the persisted position must carry the read, or the next cycle \
             re-pays the paced token"
        );
    }

    /// With no sink, nothing is written and every advance still succeeds —
    /// the property that keeps the pre-existing unbounded path unchanged.
    #[tokio::test]
    async fn no_sink_means_no_writes_and_no_failures() {
        let plan = plan_of_creates(&["a"]);
        let mut cursor = ApplyCursor::empty(plan.id);
        let mut stats = CycleStats::default();
        let state = empty_state();

        let r = record_change(&mut cursor, change_in(&plan, "a"), &state, None, &mut stats).await;

        assert_eq!(r, Recorded::Durable, "absence of a sink is not a failure");
        assert_eq!(stats.checkpoints_written, 0);
        assert_eq!(stats.checkpoint_failures, 0);
    }

    /// Nothing is checkpointed speculatively. Every change here fails (no
    /// provider), so the cursor never advances and the store is never touched
    /// — a failed node must not be recorded as applied.
    #[tokio::test]
    async fn a_cycle_that_applies_nothing_writes_no_checkpoint() {
        let plan = plan_of_creates(&["a", "b", "c"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());
        let sink = crate::checkpoint::MemoryCheckpointSink::new();
        let mut state = empty_state();

        let out =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, Some(&sink))
                .await;

        assert_eq!(out.outcome().failed.len(), 3, "control: all three failed");
        assert_eq!(
            sink.writes(),
            0,
            "a failed change must not be recorded as applied"
        );
        assert_eq!(out.stats().checkpoints_written, 0);
        assert_eq!(
            out.cursor().map(ApplyCursor::len),
            Some(0),
            "the position must not claim work the cloud never did"
        );
    }

    /// I2, at the engine level — the silent-drop seal.
    ///
    /// A cursor entry for `b` that records a DIFFERENT change than the plan's
    /// must not cause the plan's `b` to be skipped. Under the address-keyed
    /// predicate this filtered `b` out and the apply reported success having
    /// quietly not applied it; `covers` requires the content fingerprint to
    /// match, so `b` is attempted.
    #[tokio::test]
    async fn a_stale_cursor_entry_does_not_silently_drop_a_real_change() {
        let plan = plan_of_creates(&["a", "b", "c"]);
        let td = tempfile::tempdir().unwrap();
        let ctx = unpaced_ctx(td.path());

        // Record `b` as applied — but a different `b` than the plan wants.
        let mut stale = change_in(&plan, "b").clone();
        stale.after = Some(serde_json::json!({ "name": "b", "visibility": "private" }));
        let mut cursor = ApplyCursor::empty(plan.id);
        cursor.complete(&stale);
        assert!(
            cursor.contains(&repo_addr("b")),
            "the address-level predicate matches — this is the trap"
        );

        let mut state = empty_state();
        let out = run_plan_with_providers_resumable(
            &plan,
            &mut state,
            &ctx,
            Some(cursor.resume(&plan).expect("cursor is for this plan")),
            None,
            None,
        )
        .await;

        let touched: Vec<&str> = out
            .outcome()
            .failed
            .iter()
            .map(|f| f.address.name.as_str())
            .collect();
        assert!(
            touched.contains(&"b"),
            "a change the cursor did not actually record must be applied, \
             not silently skipped; attempted: {touched:?}"
        );
        assert_eq!(
            out.stats().nodes_attempted,
            3,
            "all three are outstanding — the stale entry covers none of them"
        );
    }

    // ── T4 forcing functions ───────────────────────────────────────

    // ── I4 · the wave structure is used, not discarded ─────────────

    /// The apply path never re-linearises the wave decomposition.
    ///
    /// # Tier — read this before trusting it
    ///
    /// The *accidental* flatten is already truly-unrepresentable: `Waves` and
    /// `Wave` are opaque, neither is `IntoIterator` and neither `Deref`s to a
    /// slice, so `waves.into_iter().flatten().collect()` — the exact shape of
    /// the original defect at the old engine.rs:547 — does not compile.
    ///
    /// A *deliberate* linearisation still compiles, and is meant to:
    /// `Waves::into_sequential_order` exists for the provider-free structural
    /// apply, which really is sequential. Sealing intent is not something the
    /// type system does, and is not claimed.
    ///
    /// So this is a **CI-caught forcing function**, not a compile error: it
    /// asserts the provider-backed engine — the one path where losing the wave
    /// structure would silently discard the parallelism the graph computed — is
    /// not the caller that reaches for it. Written against `include_str!`, so
    /// it is hermetic (the source is embedded at compile time; no filesystem
    /// path is resolved at run time).
    #[test]
    fn the_provider_apply_never_linearises_the_wave_decomposition() {
        // Assembled from fragments so the needles do not match this test's own
        // source text — otherwise the lint would trip on itself.
        let source = include_str!("engine.rs");
        let linearise = ["into_", "sequential_order"].concat();
        let flatten = [".flat_map(", "Wave::iter)"].concat();

        for needle in [linearise.as_str(), flatten.as_str()] {
            let hits: Vec<(usize, &str)> = source
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l.trim()))
                // A mention in prose is not a call site. Skipping comments is
                // what lets the rule be *explained* in this file without the
                // explanation tripping it.
                .filter(|(_, l)| !l.starts_with("//"))
                .filter(|(_, l)| l.contains(needle))
                .collect();
            assert!(
                hits.is_empty(),
                "the provider-backed apply must consume waves AS waves — \
                 `{needle}` collapses the dependency structure the graph just \
                 computed, which is the defect this seal exists to prevent. \
                 Found at: {hits:?}"
            );
        }
    }

    /// A graph error costs parallelism, never correctness.
    ///
    /// The latent hazard this pins: the old fallback built ONE wide wave from
    /// plan order, which *asserts an antichain* — "none of these depend on each
    /// other" — precisely the fact that just failed to be established. Harmless
    /// while execution was sequential; a concurrent executor would have acted on
    /// it and run mutually-dependent changes at once.
    ///
    /// So the fallback must have width 1. This test fails if anyone widens it.
    #[test]
    fn a_graph_error_degrades_to_width_one_never_false_parallelism() {
        let addrs: Vec<ResourceAddress> = ["a", "b", "c"].iter().map(|n| repo_addr(n)).collect();
        let waves = magma_graph::Waves::sequential(addrs.clone());

        assert_eq!(
            waves.max_width(),
            1,
            "the graph-error fallback must not claim that unordered changes are \
             independent — a concurrent executor would believe it"
        );
        assert_eq!(
            waves.iter().count(),
            addrs.len(),
            "every address becomes its own dependency step"
        );
    }

    // ── I5 · concurrency never exceeds the safe rate ───────────────

    /// The configured rate bound is *enforced*, not hoped for.
    ///
    /// Needs no provider, and that is the point: `apply_one` acquires its
    /// rate-limiter token **before** it resolves the provider, so an
    /// unreachable provider still pays the pace. The bound is therefore a
    /// property of the engine's own control flow rather than of any particular
    /// provider's behaviour, and this test measures it directly.
    ///
    /// # Scope — what this does NOT cover
    ///
    /// The **mutation** path only. `refresh_state` reads pass
    /// `None::<&LeakyBucket>` and are genuinely unpaced today; this test would
    /// not notice. Closing that needs a type — a `Paced<'_>` witness the
    /// mutating provider methods demand, which would make "forgot the pacer"
    /// a compile error instead of a reviewer's job — and that is NOT built.
    /// So the honest statement is: the mutation path's pacing is *tested*, the
    /// refresh path's absence of pacing is *known and unsealed*.
    ///
    /// # Tier
    ///
    /// Only-mitigated, and a **C2/C4 ceiling** rather than debt: the provider's
    /// true safe rate is an external-world fact discovered from response
    /// headers. What is sealed here is that the rate the engine was *told* to
    /// hold is actually held — the plumbing, not the number.
    #[tokio::test]
    async fn the_configured_rate_bound_is_enforced_not_hoped() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 60 requests/hour would be a minute apart; scale to something a test
        // can wait on: 36_000 rph = 10/s = one mutation per ~100ms.
        let ctx = unpaced_ctx(dir.path()).with_pace_rph(36_000.0);
        assert!(
            ctx.pacer.is_some(),
            "the pacer must be configured for this test to mean anything"
        );

        let plan = plan_of_creates(&["a", "b", "c"]);
        let mut state = empty_state();

        let start = std::time::Instant::now();
        let out =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;
        let elapsed = start.elapsed();

        // Three mutations at 10/s. The bucket permits an initial token
        // immediately (burst = 1), so the floor is the two *subsequent*
        // waits: >= ~200ms. Asserted with slack so a loaded machine cannot
        // make this flaky in the false-failure direction.
        assert!(
            elapsed >= std::time::Duration::from_millis(150),
            "three paced mutations finished in {elapsed:?} — the rate bound was \
             not applied; an unpaced apply is how a provider's secondary rate \
             limit gets tripped"
        );
        assert_eq!(
            out.stats().nodes_attempted,
            3,
            "all three must have been attempted — otherwise the elapsed time \
             above proves nothing about pacing"
        );
        assert!(
            out.stats().pacer_wait_ms_total >= 150,
            "the pacer wait must be MEASURED, not merely incurred — this number \
             is what decides whether concurrency could ever help; got {}ms",
            out.stats().pacer_wait_ms_total
        );
    }

    /// Turning the pacer off really does remove the bound.
    ///
    /// Without this, the test above could pass on a machine slow enough to
    /// spend 150ms doing nothing in particular — it would be measuring the
    /// machine, not the pacer. This is the negative control that makes the
    /// positive assertion mean something.
    #[tokio::test]
    async fn an_unpaced_apply_pays_no_rate_limiter_wait() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = unpaced_ctx(dir.path());
        assert!(ctx.pacer.is_none());

        let plan = plan_of_creates(&["a", "b", "c"]);
        let mut state = empty_state();
        let out =
            run_plan_with_providers_resumable(&plan, &mut state, &ctx, None, None, None).await;

        assert_eq!(
            out.stats().pacer_wait_ms_total,
            0,
            "no pacer configured must mean no pacer wait"
        );
    }
}
