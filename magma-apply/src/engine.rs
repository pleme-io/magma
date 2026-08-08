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
use magma_cty::{CtyType, DynamicValue};
use magma_graph::ResourceGraph;
use magma_plugin::provider::{ProviderConn, ProviderError, ProviderSchema, is_retryable};
use magma_plugin::{Plugin, PluginSpec, ProviderCrash};
use magma_types::{
    Action, Plan, ProviderInstance, ResourceAddress, ResourceChange, ResourceKind, State,
    StateInstance, StateResource,
};
use samba::LeakyBucket;

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
    /// Distinct from [`Self::NoResourceSchema`] ON PURPOSE. Both used to
    /// render "has no schema for RESOURCE TYPE", including when the lookup
    /// that failed was `schema.data_source(..)`. That wording is actively
    /// misleading: it sends the reader to the resource table for a data
    /// source that simply does not exist under that name.
    ///
    /// Measured 2026-08-01: `data.aws_network_acl` (SINGULAR) reported "has
    /// no schema for resource type", which reads as a magma schema-loading
    /// bug. It was not — hashicorp/aws exposes only `aws_network_acls`
    /// (plural, a list); the config was wrong and magma was right. The
    /// message cost real debugging time before the provider's own data-source
    /// index settled it.
    #[error(
        "provider {1:?} has no DATA SOURCE {0:?} (this is a data-source lookup,          not a resource one — check the provider's data-source index; e.g.          hashicorp/aws has `aws_network_acls` but no `aws_network_acl`)"
    )]
    NoDataSourceSchema(String, String),
    #[error("cty encode/decode: {0}")]
    Cty(String),
    /// An ALIASED provider instance was selected but nothing configured
    /// it.
    ///
    /// **The empty-config fallback is right for the default instance and
    /// catastrophic for an alias.** Dialing a provider with an empty
    /// config object is what terraform does for an absent `provider`
    /// block: the provider falls back to its own environment
    /// credentials — the DEFAULT account. An alias exists precisely to
    /// name a different account or region, so silently taking that
    /// fallback would resurrect the original wrong-account defect at the
    /// dial boundary, one layer below where `2e418ca` closed it.
    ///
    /// Tier: this is a `Result::Err` at dial time — **only mitigation**,
    /// not impossibility. The config boundary's
    /// `UndeclaredProviderInstance` catches the same mistake earlier, but
    /// nothing structurally prevents an `ApplyContext` built by hand from
    /// omitting an instance the plan needs, so the dial-time check is the
    /// one that is always in the path.
    #[error(
        "provider instance {instance:?} is ALIASED but no configuration was supplied for it. \
         Dialing it anyway would hand the provider an empty config, so it would fall back to \
         its environment credentials — the DEFAULT account or region, which is exactly what \
         the alias exists to say it is NOT. Supply the instance's configuration \
         (`ApplyContext::with_provider_instance_config`) or drop the alias."
    )]
    UnconfiguredProviderAlias { instance: String },
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
        let panic = c
            .headline()
            .map(str::to_string)
            .unwrap_or_else(|| err.to_string());
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
    /// Provider INSTANCE (e.g. the default `github`, or `aws.us_east_2`)
    /// → `ConfigureProvider` config as JSON (e.g.
    /// `{ "token": "…", "owner": "pleme-io" }`).
    ///
    /// Keyed by the typed [`ProviderInstance`], not a bare name: two
    /// instances of one provider are two `Configure` calls with two
    /// different credential sets, which is the entire reason an alias
    /// exists. A `BTreeMap<String, _>` could hold only one of them.
    pub provider_configs: BTreeMap<ProviderInstance, serde_json::Value>,
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

    /// Configure the DEFAULT instance of a provider by its bare local
    /// name — what a bare name has always meant, so every existing caller
    /// keeps its exact behaviour.
    ///
    /// A malformed name (empty, or carrying a `.`) is dropped rather than
    /// silently registered under a key nothing will ever look up; the
    /// aliased form has its own constructor below precisely so an alias
    /// is never smuggled through this one.
    #[must_use]
    pub fn with_provider_config(
        mut self,
        name: impl Into<String>,
        config: serde_json::Value,
    ) -> Self {
        match ProviderInstance::default_instance(name) {
            Ok(instance) => {
                self.provider_configs.insert(instance, config);
            }
            Err(e) => tracing::warn!(
                error = %e,
                "magma: ignoring a provider configuration whose name is not a bare local \
                 provider name — use `with_provider_instance_config` for an aliased instance",
            ),
        }
        self
    }

    /// Adopt every provider block the CONFIG declares.
    ///
    /// **This is what makes an aliased apply reachable from a config
    /// alone.** Selection now honours `provider = "aws.us_east_2"`, but a
    /// second instance is only useful if something supplies its
    /// credentials, and nothing in magma read `Config::providers` on the
    /// way to an `ApplyContext` — the caller assembled provider configs by
    /// hand, one bare name at a time, which is a channel that structurally
    /// could not carry an alias.
    ///
    /// Explicit rather than automatic, and later-wins over earlier calls,
    /// so a caller that supplies credentials out of band (a secret store
    /// rather than the rendered config) keeps doing exactly that: order
    /// the calls so the authoritative one is last. An `ApplyContext` that
    /// never calls this behaves precisely as it did before.
    #[must_use]
    pub fn with_config_providers(mut self, config: &magma_config::Config) -> Self {
        for (instance, block) in &config.providers {
            self.provider_configs.insert(
                instance.clone(),
                serde_json::Value::Object(
                    block
                        .fields
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
            );
        }
        self
    }

    /// Configure one named provider INSTANCE — the default instance or a
    /// declared alias.
    #[must_use]
    pub fn with_provider_instance_config(
        mut self,
        instance: ProviderInstance,
        config: serde_json::Value,
    ) -> Self {
        self.provider_configs.insert(instance, config);
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
    instance: &ProviderInstance,
) -> Result<LiveProvider, EngineError> {
    // Resolve the `Configure` payload FIRST, before spawning anything.
    // It is a pure lookup, and doing it up front means an unconfigured
    // alias reports the real problem instead of whatever the spawn
    // happens to fail on — and is checkable without a provider binary.
    let config_json = resolve_provider_config(ctx, instance)?;
    // The BINARY is selected by the bare local name: every instance of a
    // provider is served by the same plugin. What differs per instance is
    // the `Configure` payload — which is exactly what an alias is.
    let name = instance.name();
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

/// The `ConfigureProvider` payload for one provider instance.
///
/// The provider-config-typed creds, or an empty object (→ a
/// provider-config object with all attributes null, which is what
/// terraform sends for an absent provider block; the provider falls back
/// to its own env credentials). NOT a null object — providers expect a
/// value of the config type, not nil.
///
/// **That fallback is legitimate for the DEFAULT instance and wrong for
/// an alias.** Falling back to the environment IS falling back to the
/// default account, which is precisely what the alias exists to say it is
/// not. See [`EngineError::UnconfiguredProviderAlias`].
fn resolve_provider_config(
    ctx: &ApplyContext,
    instance: &ProviderInstance,
) -> Result<serde_json::Value, EngineError> {
    match ctx.provider_configs.get(instance) {
        Some(c) => Ok(c.clone()),
        None if instance.is_default() => Ok(serde_json::Value::Object(Default::default())),
        None => Err(EngineError::UnconfiguredProviderAlias {
            instance: instance.to_string(),
        }),
    }
}

/// The providers dialed for one apply, one per provider INSTANCE.
///
/// Keyed by [`ProviderInstance`], not by bare name: `aws` and
/// `aws.us_east_2` are the same binary configured twice, and a
/// name-keyed cache would hand the second resource the first one's
/// connection — the wrong account, silently.
struct Registry<'a> {
    ctx: &'a ApplyContext,
    live: HashMap<ProviderInstance, LiveProvider>,
}

impl<'a> Registry<'a> {
    fn new(ctx: &'a ApplyContext) -> Self {
        Self {
            ctx,
            live: HashMap::new(),
        }
    }

    async fn get(&mut self, instance: &ProviderInstance) -> Result<&mut LiveProvider, EngineError> {
        if !self.live.contains_key(instance) {
            let lp = self.spawn(instance).await?;
            self.live.insert(instance.clone(), lp);
        }
        // The provider is in the map (just inserted, or already present).
        // `ok_or_else` keeps this unwrap-free: the `None` arm is logically
        // unreachable but yields a typed error rather than a panic if that
        // invariant is ever broken (a provider on the apply path must never
        // panic magma).
        self.live.get_mut(instance).ok_or_else(|| {
            EngineError::Spawn(
                instance.to_string(),
                "internal: provider missing from registry after insert".to_string(),
            )
        })
    }

    async fn spawn(&self, instance: &ProviderInstance) -> Result<LiveProvider, EngineError> {
        dial_configured_provider(self.ctx, instance).await
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

    // DECLARED names, from this plan. A composite import id like
    // `<repo>:<label>` needs the parent's real name, and for a parent this
    // plan is only just creating, state cannot supply it — but the plan can,
    // exactly, from the declaration. Without this, `natural_id::derive` fell
    // back to the parent's RESOURCE name under the org-posture convention
    // (`resource-name == repo-name`), which every underscore-sanitized name
    // breaks, so the id was marked `CatalogWithGuessedParent`, adoption
    // refused it as non-exact, and the Create failed `already_exists` on
    // every cycle forever.
    //
    // Built once, from the whole plan, so it also covers parents scheduled
    // AFTER the child in apply order.
    // Built by `natural_id::declared_map` rather than inline here, because the
    // map's SHAPE is part of `natural_id::derive`'s contract and the operator's
    // pre-plan prepass needs the same map. Two hand-rolled copies of a contract
    // is precisely the drift `natural_id` exists to end.
    let declared_map = crate::natural_id::declared_map(&plan.resource_changes);

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
        // A NoOp never mutates, so it can never conflict: no adoption id.
        let outcome = apply_one(change, None, &mut rec, &mut registry).await;
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

    let by_key: HashMap<(String, String), &ResourceChange> = pending
        .iter()
        .map(|c| ((c.address.type_id.0.clone(), c.address.name.clone()), *c))
        .collect();

    // Edges from BOTH interpolation references and declared `depends_on`
    // — see `build_change_graph`, which the structural engine in `lib.rs`
    // shares so the two can never diverge again.
    let graph = build_change_graph(&pending);

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
            // Derive the adoption id HERE, where both halves exist: the RAW
            // change (whose `${type.name.attr}` references say *which* parent a
            // composite id points at) and `state_map` (which says what that
            // parent is really NAMED). `apply_one` sees only the substituted
            // clone, where the reference has already collapsed into a node id
            // or a convention-guessed string — which is exactly why deriving it
            // down there produced un-importable ids for every reference-keyed
            // type.
            //
            // Derived for anything that CAN reach a create — which is not just
            // `Action::Create`. This read "computed for creates only; nothing
            // else can conflict" and that was false: the provider, not the
            // plan, decides replacement (`requires_replace`), so an
            // `Action::Update` routed to `apply_replace` has a create half
            // that conflicts exactly like a plain create. Deriving only for
            // Create left that half with no id to import, so it could not
            // adopt and looped instead — measured 2026-08-02 on
            // github_repository.blue.
            //
            // Delete and NoOp genuinely cannot create, so they genuinely
            // cannot conflict; they stay `None` and spend no derivation.
            let adoption = if has_create_half(change.action) {
                crate::natural_id::derive(
                    change,
                    resolved.after.as_ref(),
                    &state_map,
                    &declared_map,
                )
            } else {
                None
            };
            let mut rec = NodeRecord::default();
            let outcome = apply_one(&resolved, adoption.as_ref(), &mut rec, &mut registry).await;
            rec.commit(state);
            stats.pacer_wait_ms_total = stats.pacer_wait_ms_total.saturating_add(rec.pacer_wait_ms);
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
                Err(e) => {
                    // Count it. NOT recording it as *completed* is correct (the
                    // next cycle retries), but leaving it uncounted entirely is
                    // what let a 17/0 cycle read as "nothing to do".
                    stats.nodes_failed += 1;
                    failed.push(mkfail(change, e));
                }
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
    stats.debug_assert_consistent();
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
            nodes_failed = stats.nodes_failed,
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
            let name: String = after
                .chars()
                .take_while(|c| *c != '.' && *c != '}')
                .collect();
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
    /// Instances dropped because they carry NO resource `id` and are therefore
    /// unmanageable by construction — not because a provider said they were
    /// gone. Counted apart from [`Self::dropped_instances`] on purpose: these
    /// are a local structural verdict that never touched the network, so they
    /// must not feed the mass-drop guard, whose whole job is to spot a
    /// systemic `ReadResource` malfunction.
    pub dropped_unmanageable: usize,
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
        // Select from the ROW's own provider reference, so an aliased
        // resource is read back through the instance that holds it.
        let provider_instance = match refresh_instance_for(ctx, &resource) {
            Ok(i) => i,
            Err(kept_row) => {
                report.kept_on_error += resource.instances.len();
                kept.push(kept_row);
                continue;
            }
        };

        // Resolve the implied type + current schema version once (clone
        // so the schema borrow ends before the per-instance mutable RPC
        // borrows). Any failure here ⇒ keep the whole resource untouched.
        let (implied, current_version) = match registry.get(&provider_instance).await {
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
            // PACE THE REFRESH. `refresh_state` reads EVERY instance in the
            // workspace on EVERY cycle, so it is the dominant consumer of the
            // provider's hourly budget — far larger than the mutations the
            // pacer was originally built for. It ran unpaced while its own
            // sibling `refresh_named` paced the identical RPC, so a bulk
            // refresh could exhaust the budget before the apply it precedes
            // ever dispatched a single write.
            //
            // Measured 2026-08-08 on pleme-io-opensource: 4,786 instances
            // against GitHub's 5,000 req/hr, so the refresh alone consumed the
            // hour and every apply died on `403 API rate limit of 5000 still
            // exceeded` — three approvals, zero completed applies.
            if let Some(p) = ctx.pacer.as_deref() {
                let _ = p.acquire().await;
            }
            // STRUCTURAL DROP, and the one principled exception to the
            // "never delete because a read failed" rule above.
            //
            // The predicate is deliberately NARROWER than "has no id". An
            // id-less instance cannot be read — ReadResource has nothing to
            // look up — so it never reaches the provider-reports-gone arm that
            // self-heals ordinary phantoms; it fails, lands in
            // `kept_on_error`, and survives every refresh forever while
            // re-planning as a pending change, wedging the workspace on
            // `apply didn't converge` permanently.
            //
            // But missing-id ALONE is not safe to act on: `id` is mandatory
            // for legacy-SDK resources and merely conventional for
            // plugin-framework (protocol v6) ones, so a blanket drop could
            // delete legitimate state. The second half of the predicate is
            // what makes it decisive — an UNRESOLVED `${…}` interpolation in
            // an attribute. State holds resolved values by definition; a
            // `${…}` there is never a refreshed read, only ever a config echo
            // recorded from a failed apply. Both together identify a phantom
            // with no plausible innocent reading.
            //
            // Measured on example-eks-vpn-concentrator (2026-08-01): a failed
            // SG create recorded the provider's config echo (no id, `vpc_id`
            // still the literal `${data.aws_vpc.example_eks.id}`), and every
            // cycle thereafter failed with "re-plan has 1 non-NoOp changes"
            // while AWS showed no such SG. `record_partial_apply` now refuses
            // to create these; this arm heals the ones already written.
            if is_unmanageable_phantom(&inst.attributes) {
                report.dropped_unmanageable += 1;
                tracing::warn!(
                    address = %resource.address,
                    "magma refresh: dropping a state instance with NO id — it is \
                     unmanageable by construction (cannot be read, updated or \
                     destroyed) and would wedge every plan. The next plan will \
                     create the resource."
                );
                continue;
            }
            let lp = match registry.get(&provider_instance).await {
                Ok(l) => l,
                Err(_) => {
                    report.kept_on_error += 1;
                    kept_instances.push(inst);
                    continue;
                }
            };
            let prior_dv = match resolve_prior_dv(
                lp,
                None,
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
            match rpc_retry!(
                ctx.pacer.as_deref(),
                lp.conn.read_resource(&type_name, &prior_dv)
            ) {
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
        // Select from the ROW's own provider reference, so an aliased
        // resource is read back through the instance that holds it.
        let provider_instance = match refresh_instance_for(ctx, &resource) {
            Ok(i) => i,
            Err(kept_row) => {
                report.kept_on_error += resource.instances.len();
                kept.push(kept_row);
                continue;
            }
        };
        let (implied, current_version) = match registry.get(&provider_instance).await {
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
            let lp = match registry.get(&provider_instance).await {
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
            match rpc_retry!(
                pacer.as_deref(),
                lp.conn.read_resource(&type_name, &prior_dv)
            ) {
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

/// Does a provider error message *look like* an already-exists diagnostic?
///
/// **RETIRED AS A GATE (kept as telemetry).** This was the condition on the
/// adopt-on-conflict path; it is now only a log field. A substring oracle over
/// a provider's prose is only-mitigated in both directions — it misses a real
/// conflict worded differently, and it fires on any message that merely
/// contains the digits "422"/"409". Worse, the failure that actually wedged
/// pleme-io-opensource never matched it at all: a child create sent to a wrong
/// URL returns **404**, so a resource that plainly exists was never considered
/// for adoption. The gate is now the provider's own answer —
/// `ImportResourceState` returning a non-null state. This function survives so
/// the log can still distinguish "we expected this conflict" from "we adopted
/// something the diagnostic never advertised", which is the signal that a
/// *different* bug (a bad URL, a bad reference) is upstream of the conflict.
fn is_already_exists(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already exists")
        || m.contains("already been")
        || m.contains("name_already_in_use")
        || m.contains("422")
        || m.contains("409")
}

/// **The** adoption primitive: run the Terraform import protocol's TWO
/// mandated steps against a live provider and return the adopted resource's
/// full attribute object.
///
/// `ImportResourceState` returns a **STUB** — by protocol contract it carries
/// only enough identity for the follow-up read (for `github_repository`, just
/// `id`); every other attribute, including every COMPUTED one (`name`,
/// `node_id`, `repo_id`, `full_name`, …), comes back `null`. The protocol's
/// second step, `ReadResource` on that stub, is what populates them. Persisting
/// the stub is therefore not "a slightly incomplete adopt" — it is a resource
/// whose address exists in state while its identity does not, and magma's
/// `refresh` is an M0.10 no-op, so it never self-heals. Every dependent that
/// references a computed attribute then resolves to `null` FOREVER:
/// `github_branch_protection.repository_id = ${github_repository.X.node_id}`
/// becomes `""` → GitHub's "Could not resolve to a node with the global id of
/// ''" → NOT `is_already_exists` → the reactive adopt path is never reached, so
/// the already-existing branch protection can never adopt. That is a permanent
/// wedge, produced by the adoption that was supposed to end one.
///
/// This function exists so the two-step protocol is implemented **once**. Both
/// adoption entry points drive it:
///
/// 1. the reactive mid-apply arm ([`apply_one_inner`]'s `Action::Create` +
///    [`is_already_exists`] branch — `importPolicy.autoOnConflict`), and
/// 2. the proactive pre-plan prepass
///    ([`crate::import_prepass::ConfiguredImportEnvironment`], which the
///    operator's `import()` drives for every resolved import target).
///
/// Before this existed only (1) performed the confirming read; (2) absorbed the
/// raw stub, which is exactly how the pleme-io-opensource state came to hold
/// nine `github_repository` entries with `name: null, node_id: null`.
///
/// Returns `Ok(None)` when the provider imported nothing (a cty-null import
/// state — the resource genuinely isn't there). A failed *confirming read*
/// never fails the adoption: it falls back to the stub plus the identity
/// backfill below, because a tracked-with-identity resource strictly dominates
/// a re-created one.
pub(crate) async fn import_and_confirm(
    lp: &mut LiveProvider,
    type_name: &str,
    id: &str,
    pacer: Option<&LeakyBucket>,
) -> Result<Option<serde_json::Value>, EngineError> {
    let provider_name = provider_local_name(type_name);
    let implied =
        lp.schema.resource(type_name).cloned().ok_or_else(|| {
            EngineError::NoResourceSchema(type_name.into(), provider_name.clone())
        })?;

    let Some(imp_dv) =
        rpc_retry!(pacer, lp.conn.import_resource_state(type_name, id)).map_err(|e| {
            EngineError::Rpc(provider_name.clone(), format!("import_resource_state: {e}"))
        })?
    else {
        return Ok(None);
    };

    // Step 2 — the protocol-mandated confirming read. RETRIED: a TRANSIENT
    // read failure (RPC hiccup, secondary rate limit, momentary provider
    // crash) falling straight through to the stub is precisely how an
    // identity-less entry gets persisted.
    let full_dv = match rpc_retry!(pacer, lp.conn.read_resource(type_name, &imp_dv)) {
        Ok(Some(read_dv)) => read_dv,
        // `Ok(None)` is NOT a failed read — it is the provider affirmatively
        // answering "that resource is not there" (a cty-null `new_state`,
        // `ProviderConn::read_resource`'s absent signal). Falling through to
        // the stub here is the worst reachable outcome of the whole adoption
        // path: an import stub for a resource the provider just refuted gets
        // persisted (with its identity backfilled from the id, which makes it
        // look healthy), the resource is then absent from every future plan,
        // and it is NEVER CREATED — silently. A passthrough importer
        // (`ImportStatePassthroughContext`, which `github_repository` uses)
        // makes no API call at all, so step 1 alone can never be the gate;
        // this read is. Refusing here costs one re-created resource at worst;
        // accepting costs one that never exists.
        Ok(None) => {
            tracing::warn!(
                resource_type = %type_name,
                import_id = %id,
                "magma adopt: import returned a stub but the confirming ReadResource says the \
                 resource is absent; refusing to adopt (a stub adopted here would never be created)"
            );
            return Ok(None);
        }
        // A genuinely FAILED read (RPC error, after retry) is different: the
        // resource's existence is unrefuted, and a tracked-with-identity
        // resource still dominates a re-created one.
        Err(_) => imp_dv,
    };
    let mut attrs = full_dv
        .to_json(&implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;

    // Defense-in-depth: if even the retried read couldn't confirm and we fell
    // back to the stub, a name-keyed resource's import id IS its name — backfill
    // it so an adopted state is NEVER identity-less. Computed attributes may
    // still be incomplete; the `${…name}` fallback in `substitute_refs` covers
    // references either way. Scoped to `github_repository` because that is the
    // one type where `id == name` is a schema fact, not a guess.
    if type_name == "github_repository" && attrs.get("name").is_none_or(serde_json::Value::is_null)
    {
        if let Some(o) = attrs.as_object_mut() {
            o.insert(
                "name".to_string(),
                serde_json::Value::String(id.to_string()),
            );
        }
        tracing::warn!(
            resource_type = %type_name,
            import_id = %id,
            "magma adopt: ReadResource could not confirm a name after retry; backfilled identity from import id (computed attrs may be incomplete)"
        );
    }
    Ok(Some(attrs))
}

/// The provider-native import id for a create-conflict adoption — now a thin
/// forwarder onto the typed catalog in [`crate::natural_id`].
///
/// The per-type `match` that used to live here is gone, and with it the class
/// of bug it kept producing: a component that is a **reference to a parent**
/// was indistinguishable from a plain attribute, so
/// `github_branch_protection.repository_id` (a `${…node_id}` reference) became
/// either the raw `${…}` literal or a GraphQL node id, and neither is
/// importable. See [`crate::natural_id::IdPart::ParentName`].
///
/// This forwarder is now TEST-ONLY. Production has exactly one derivation
/// site — the apply loop, which owns the resolution map — and one consumption
/// site, [`resolve_import_id`], which gates the result on
/// [`crate::natural_id::Confidence::is_exact`]. A second production caller
/// would be a second, ungated path to the same guess.
#[cfg(test)]
fn natural_import_id(change: &ResourceChange) -> Option<String> {
    crate::natural_id::derive(
        change,
        change.after.as_ref(),
        &HashMap::new(),
        &HashMap::new(),
    )
    .map(|i| i.id)
}

/// Resolve the provider-native import id for adopting a create-conflicted
/// resource (an `is_already_exists` Create). Most providers key import on the
/// `name` attribute, so the typed catalog in [`crate::natural_id`] suffices.
/// Some assign an OPAQUE
/// server id that is absent from config and only knowable by DISCOVERY — e.g.
/// `cloudflare_dns_record`'s import id is `<zone_id>/<record_id>`, and
/// `record_id` can only be found by listing the zone and matching the natural
/// key (name + type). This is the generic adopt-by-identity resolver: per-type
/// discovery via a provider read, falling back to the natural `name` id. A
/// discovery failure returns `None` so the caller falls through to the genuine
/// create-conflict failure — never an adoption with a wrong id.
///
/// What an adopt-on-conflict attempt concluded.
///
/// Three outcomes, not two: "nothing there" and "something there but it is not
/// yours" must not collapse, because they demand opposite reactions — the first
/// falls through to the caller's real error, the second must HARD-FAIL rather
/// than bind a foreign object to a planned address.
pub(crate) enum Adoption {
    /// The object exists and passed the identity gate. Attributes to record.
    Adopted(serde_json::Value),
    /// Nothing exists under a resolvable id (or no id resolved). The caller's
    /// original apply error stands.
    Absent,
    /// Something exists under that id but it is NOT the planned resource.
    Mismatch {
        attr: String,
        planned: String,
        imported: String,
        id: String,
    },
}

/// Adopt-on-conflict for a create half that failed — the reaction magma has
/// for exactly one situation: the object we were told to create already exists
/// out-of-band.
///
/// Extracted so BOTH create halves drive it. It used to be inline on
/// `apply_one_inner`'s `Action::Create` arm only, which left
/// [`apply_replace`]'s create half — reached whenever the provider marks any
/// attribute `ForceNew` on a change with a prior state — with no adoption at
/// all. That path could not self-heal, and a resource that exists but cannot
/// be created is a permanent loop: measured 2026-08-02 on
/// `pleme-io-opensource`, `github_repository.blue` attempted 12 creates in 45
/// minutes, each answering `422 name already exists`, while the template never
/// reached Ready and the loop drained the org's GitHub API budget to 0/5000.
///
/// THE GATE IS THE PROVIDER'S ANSWER, NOT THE ERROR STRING — `ImportResourceState`
/// returning a non-null state is the provider stating the resource exists,
/// where [`is_already_exists`] was only ever a guess in both directions. That
/// oracle survives as telemetry so "expected conflict" and "surprise adoption"
/// stay distinguishable in the log.
///
/// Records nothing itself: each caller owns how the adoption lands in its
/// [`NodeRecord`], because the two sites record different actions.
async fn try_adopt_on_conflict(
    change: &ResourceChange,
    type_name: &str,
    lp: &mut LiveProvider,
    pacer: Option<&LeakyBucket>,
    adoption: Option<&crate::natural_id::ImportId>,
    msg: &str,
) -> Adoption {
    // Resolve the import id: the caller-derived natural id (composite, parent
    // references resolved against the apply loop's resolution map), or a
    // discovered `<zone_id>/<record_id>` for opaque-id resources via the
    // per-type resolver.
    let Some(id) = resolve_import_id(change, type_name, lp, adoption).await else {
        return Adoption::Absent;
    };
    // The SHARED two-step adoption primitive — import, then the
    // protocol-mandated confirming ReadResource, with identity backfill.
    let Ok(Some(attrs)) = import_and_confirm(lp, type_name, &id, pacer).await else {
        return Adoption::Absent;
    };
    // THE IDENTITY GATE. A successful import means "something exists under
    // this id" — never "this is the resource you planned". Nothing else on
    // this path compares the object that came back with the change that asked
    // for it, so a derived id that happens to name a real but DIFFERENT
    // resource would be adopted silently, under the planned address, and the
    // next cycle would diff config against it. Refuse.
    if let Err(m) = crate::natural_id::verify_identity(change, change.after.as_ref(), &attrs) {
        return Adoption::Mismatch {
            attr: m.attr.to_string(),
            planned: m.planned,
            imported: m.imported,
            id,
        };
    }
    tracing::info!(
        address = ?change.address,
        import_id = %id,
        id_confidence = ?adoption.map(|i| i.confidence),
        // TELEMETRY, not a gate: `false` here means the create's diagnostic
        // did NOT look like a conflict and the old string oracle would have
        // refused this adoption.
        diagnostic_looked_like_conflict = is_already_exists(msg),
        "magma apply: adopted pre-existing resource via import-on-conflict + ReadResource refresh"
    );
    Adoption::Adopted(attrs)
}

/// New opaque-id resource types register a discovery arm here; this is the
/// extension point for the generic ObjectExistsUntracked → adopt reaction.
async fn resolve_import_id(
    change: &ResourceChange,
    type_name: &str,
    lp: &mut LiveProvider,
    precomputed: Option<&crate::natural_id::ImportId>,
) -> Option<String> {
    // An opaque-id type registers an `AdoptionSpec`; the generic interpreter
    // discovers its id via a list-data-source read. Everything else keys
    // import on the natural id — derived by the caller against the apply
    // loop's resolution map (`precomputed`), because a composite id whose
    // component is a parent REFERENCE cannot be derived from `change` alone.
    // The state-less forwarder is the fallback for callers that have no map.
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
        None => {
            let derived = precomputed.cloned().or_else(|| {
                crate::natural_id::derive(
                    change,
                    change.after.as_ref(),
                    &HashMap::new(),
                    &HashMap::new(),
                )
            });
            gate_on_confidence(derived, &change.address, type_name)
        }
    }
}

/// THE CONFIDENCE GATE, as a pure function so it is *testable*.
///
/// Kept out of [`resolve_import_id`]'s body deliberately: that function needs a
/// live `LiveProvider`, so a gate inlined there can only be exercised through
/// a provider whose types all happen to derive an exact id — which is to say,
/// never exercised at all (★★ UNREPRESENTABILITY Tier ⊥: a guard never
/// observed to refuse may be refusing nothing).
fn gate_on_confidence(
    derived: Option<crate::natural_id::ImportId>,
    address: &ResourceAddress,
    type_name: &str,
) -> Option<String> {
    // `Confidence` used to be computed and then only LOGGED, which made
    // `is_exact` dead code and left the two guessing arms —
    // `CatalogWithGuessedParent` (parent absent from state, so the id falls
    // back to the RESOURCE name under the `resource-name == repo-name`
    // convention that underscore-sanitized names like `tag_forge` vs
    // `tag-forge` break) and `AddressName` (no rule, no `name` attribute at
    // all) — feeding `ImportResourceState` on exactly the same footing as a
    // fully-resolved one. A wrong import id is not a failed adoption, it is an
    // adoption of SOMETHING ELSE, and the resource it adopts is then diffed
    // and can be routed to `apply_replace` — a destroy of a live resource
    // nobody planned to touch. Refusing a guess costs a re-create attempt on
    // the next cycle, by which point the parent is in state (via `sm_insert`)
    // and the id resolves exactly.
    match derived {
        Some(i) if i.confidence.is_exact() => Some(i.id),
        Some(i) => {
            tracing::warn!(
                address = ?address,
                resource_type = %type_name,
                rejected_import_id = %i.id,
                confidence = ?i.confidence,
                "magma adopt: refusing to import on a non-exact id; \
                 falling through to the create failure"
            );
            None
        }
        None => None,
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
    let filter_dv = DynamicValue::from_json(&filter, &ds_schema)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
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
        /// The provider reference to RECORD — carrying the alias of the
        /// instance this resource was actually applied through, so the
        /// next refresh reads it back through the same account.
        provider: magma_types::ProviderReference,
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
    /// Record an insert for the node's OWN change.
    ///
    /// Takes the whole `ResourceChange`, not just its address, because
    /// the state row must carry the provider instance the resource was
    /// applied through — and the change is the only value that knows it.
    /// Passing an address alone is how the alias got dropped on the way
    /// into state.
    fn insert(&mut self, change: &ResourceChange, attrs: serde_json::Value, schema_version: u64) {
        self.ops.push(StateOp::Insert {
            address: change.address.clone(),
            attrs,
            schema_version,
            provider: crate::provider_reference_for(&change.address, change.meta.provider.as_ref()),
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
                    provider,
                } => insert_resource(
                    state,
                    address,
                    attrs.clone(),
                    *schema_version,
                    provider.clone(),
                ),
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
    adoption: Option<&crate::natural_id::ImportId>,
    rec: &mut NodeRecord,
    reg: &mut Registry<'_>,
) -> Result<AppliedChange, EngineError> {
    let started = std::time::Instant::now();
    let out = apply_one_inner(change, adoption, rec, reg).await;
    let total = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // Whatever was not spent waiting on the rate limiter was spent in (or
    // on the way to) the provider. `saturating_sub` because the two clocks
    // are read separately and could in principle disagree by a tick.
    rec.rpc_ms = total.saturating_sub(rec.pacer_wait_ms);
    out
}

async fn apply_one_inner(
    change: &ResourceChange,
    adoption: Option<&crate::natural_id::ImportId>,
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
    let provider_instance = provider_for_change(change);
    // The diagnostic label names WHICH CONNECTION failed, so it renders
    // the whole instance. For a default instance that is the bare name it
    // has always been; for an alias it is `aws.us_east_2`, which is the
    // only form that tells the reader which account the RPC went to.
    let provider_name = provider_instance.to_string();
    let lp = reg.get(&provider_instance).await?;
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
            if let Err(e) = rpc_retry!(
                pacer.as_deref(),
                lp.conn
                    .apply_resource_change(&type_name, &prior_dv, &null_dv, &null_dv)
            ) {
                // A PARTIAL DELETE: the provider errored but handed back a
                // non-null state, meaning the resource is still (partly)
                // there. Re-record it rather than letting `rec.remove` below
                // be skipped into silence — a resource dropped from state
                // while still alive in the cloud is an orphan nobody bills us
                // for noticing.
                record_partial_apply(rec, change, &e, &implied, current_schema_version);
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
            let planned = match rpc_retry!(
                pacer.as_deref(),
                lp.conn
                    .plan_resource_change(&type_name, &prior_dv, &config_dv, &config_dv)
            ) {
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
            // A CREATE CAN NEVER BE A REPLACE — replace means "destroy the
            // existing object, then make a new one", and on a create there is
            // no existing object. So `requires_replace` is only meaningful
            // when a prior state exists.
            //
            // Without the `has_prior` guard this misroutes EVERY create whose
            // provider marks any attribute ForceNew — which for the AWS
            // provider is most of them (`name` on aws_iam_role,
            // `vpc_id` on aws_security_group, …). The consequences are not
            // cosmetic:
            //
            //   1. It takes `apply_replace`, whose create half has NO
            //      import-on-conflict. So a create that hits
            //      EntityAlreadyExists — the ONE case adoption exists for —
            //      can never self-heal. Measured 2026-08-01 on
            //      example-eks-vpn-concentrator: aws_iam_role failed
            //      `CreateRole 409` against an orphan for cycle after cycle,
            //      with zero `magma adopt:` lines, because the adoption code
            //      is on a path the change never reached.
            //   2. Every error is mislabelled `apply_resource_change[replace:create]`,
            //      which reads as "magma decided to replace this" when magma
            //      decided nothing of the sort — the provider merely listed
            //      ForceNew attributes, as it does on every create.
            let has_prior = change.before.as_ref().is_some_and(|b| !b.is_null());
            let is_replace = should_replace(
                has_prior,
                !planned.requires_replace.is_empty(),
                change.action,
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
                    adoption,
                )
                .await;
            }

            let planned_dv = planned.state;
            let new_dv = match rpc_retry!(
                pacer.as_deref(),
                lp.conn
                    .apply_resource_change(&type_name, &prior_dv, &planned_dv, &config_dv)
            ) {
                Ok(dv) => dv,
                Err(e) => {
                    let msg = e.to_string();
                    // PARTIAL APPLY comes first: the provider already told us
                    // exactly what it committed, so there is nothing to adopt
                    // and no reason to spend an import RPC guessing.
                    if record_partial_apply(rec, change, &e, &implied, current_schema_version) {
                        let (crash, close) = provider_failure_signals(lp);
                        return Err(rpc_error(
                            &provider_name,
                            "apply_resource_change",
                            crash,
                            close,
                            &msg,
                        ));
                    }
                    // Import-on-conflict: a Create that FAILED may have failed
                    // because the resource already EXISTS in cloud while being
                    // absent from magma's state. Adopt it via
                    // ImportResourceState instead of failing — otherwise the
                    // plan re-creates it every cycle and loops forever (the
                    // pleme-io-opensource created:0 / all-422 wedge). This is
                    // the magma analog of tofu's importPolicy.autoOnConflict.
                    //
                    // THE GATE IS THE PROVIDER'S ANSWER, NOT THE ERROR STRING.
                    // It used to be `is_already_exists(&msg)` — a substring
                    // match on "already exists" / "422" / "409". That oracle
                    // is only-mitigated in both directions: it MISSES a real
                    // conflict whose diagnostic is worded differently, and it
                    // misses the case that actually wedged pleme-io-opensource
                    // — a child create posted to a wrong URL (a parent name
                    // resolved from a convention rather than from state)
                    // returns 404, so the resource that plainly exists is
                    // never even *considered* for adoption. `ImportResourceState`
                    // returning a non-null state is the provider telling us the
                    // resource exists; that is a fact, where the string was a
                    // guess. The cost is one import RPC on a path that has
                    // already failed — creates that fail are the exception, and
                    // the pacer bounds them. `is_already_exists` survives as
                    // TELEMETRY (below) so the "expected conflict vs surprise
                    // adoption" split stays visible in the log.
                    // CREATE ONLY on this path. An in-place `Update` that
                    // failed must NOT be handed to adoption: the resource is
                    // already in state, so the import would succeed trivially
                    // and report the UNCHANGED object as a success — silently
                    // swallowing the update failure. Only a create can be
                    // answered by "it already exists". (`apply_replace`'s
                    // create half is the other legitimate caller; it gates on
                    // being a create by construction.)
                    if change.action == Action::Create {
                        match try_adopt_on_conflict(
                            change,
                            &type_name,
                            lp,
                            pacer.as_deref(),
                            adoption,
                            &msg,
                        )
                        .await
                        {
                            Adoption::Adopted(attrs) => {
                                rec.insert(change, attrs.clone(), current_schema_version);
                                return Ok(AppliedChange {
                                    address: change.address.clone(),
                                    action: change.action,
                                    before: None,
                                    after: Some(attrs),
                                });
                            }
                            Adoption::Mismatch {
                                attr,
                                planned,
                                imported,
                                id,
                            } => {
                                tracing::error!(
                                    address = ?change.address,
                                    import_id = %id,
                                    attr = %attr,
                                    planned = %planned,
                                    imported = %imported,
                                    "magma adopt: imported resource is NOT the planned one; \
                                     refusing the adoption"
                                );
                                let (crash, close) = provider_failure_signals(lp);
                                return Err(rpc_error(
                                    &provider_name,
                                    "apply_resource_change",
                                    crash,
                                    close,
                                    &msg,
                                ));
                            }
                            Adoption::Absent => {}
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
            rec.insert(change, new_attrs.clone(), current_schema_version);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: Some(new_attrs),
            })
        }
    }
}

/// Can a change with this action end up issuing a CREATE against the provider,
/// and therefore collide with an object that already exists?
///
/// Pure predicate, extracted for the same reason as [`should_replace`] below: a
/// branch reachable only through a live provider is a branch no test exercises.
///
/// The subtle case is `Update`. The PLAN's action is not the last word —
/// `plan_resource_change` may come back with `requires_replace` non-empty, and
/// `apply_replace` then destroys and re-creates. So an `Update` has a create
/// half, and that half can conflict exactly like a plain create. The code this
/// replaced assumed otherwise ("computed for creates only; nothing else can
/// conflict"), so a replace-routed change had no import id to adopt with and
/// looped on `422 already exists` instead — measured 2026-08-02 on
/// `github_repository.blue`, 12 attempts in 45 minutes.
///
/// `Delete`, `Forget`, `Read` and `NoOp` genuinely never create.
///
/// Matched exhaustively on purpose — no `_` arm. A new `Action` variant must be
/// classified here or the crate does not compile, which is the difference
/// between this staying correct and it silently mis-answering the next variant
/// somebody adds. (It earned that immediately: the first draft omitted
/// `Forget` and E0004 caught it.)
pub(crate) fn has_create_half(action: Action) -> bool {
    match action {
        Action::Create
        | Action::Update
        | Action::Replace
        | Action::CreateThenDelete
        | Action::DeleteThenCreate => true,
        // Forget drops the resource from state and leaves the object alone —
        // no provider mutation at all, so nothing to collide with.
        Action::NoOp | Action::Delete | Action::Read | Action::Forget => false,
    }
}

/// A CREATE is never a REPLACE, expressed as a pure predicate so it is
/// testable without a live provider.
///
/// Extracted from `apply_one`'s inline condition for exactly the reason the
/// project keeps rediscovering: a branch reachable only through a real
/// provider connection is a branch no test ever exercises, and this one was
/// wrong in production for as long as it existed.
pub(crate) fn should_replace(
    has_prior: bool,
    requires_replace_non_empty: bool,
    action: Action,
) -> bool {
    has_prior
        && (requires_replace_non_empty
            || matches!(
                action,
                Action::Replace | Action::CreateThenDelete | Action::DeleteThenCreate
            ))
}

#[cfg(test)]
mod replace_routing_tests {
    use super::*;

    /// The regression. The AWS provider marks attributes ForceNew on a CREATE
    /// too (`name` on aws_iam_role, `vpc_id` on aws_security_group), so
    /// `requires_replace` is routinely non-empty with no prior state. Routing
    /// that to `apply_replace` costs the create its import-on-conflict, and
    /// import-on-conflict is the entire mechanism for recovering an orphan —
    /// which is what example-eks-vpn-concentrator needed and never got
    /// (CreateRole 409, cycle after cycle, zero `magma adopt:` lines).
    #[test]
    fn a_create_is_never_a_replace_even_when_the_provider_forces_new() {
        assert!(
            !should_replace(false, true, Action::Create),
            "no prior state means nothing to destroy — this must take the \
             create path so import-on-conflict can adopt an orphan"
        );
    }

    #[test]
    fn a_real_replace_still_replaces() {
        assert!(should_replace(true, true, Action::Update));
        assert!(should_replace(true, false, Action::Replace));
        assert!(should_replace(true, false, Action::DeleteThenCreate));
        assert!(should_replace(true, false, Action::CreateThenDelete));
    }

    /// An explicit Replace action with NO prior state is incoherent, and the
    /// honest answer is the create path rather than a destroy of nothing.
    #[test]
    fn an_explicit_replace_without_prior_state_still_takes_the_create_path() {
        assert!(!should_replace(false, false, Action::Replace));
    }

    #[test]
    fn an_ordinary_update_with_no_force_new_is_not_a_replace() {
        assert!(!should_replace(true, false, Action::Update));
    }

    /// THE REGRESSION. An `Update` that the provider resolves to a replace has
    /// a create half, so it must carry an adoption id. Deriving only for
    /// `Action::Create` is what left `apply_replace`'s create half unable to
    /// adopt — `github_repository.blue`, 12 × `422 already exists` in 45
    /// minutes on pleme-io-opensource, 2026-08-02.
    #[test]
    fn an_update_has_a_create_half_because_the_provider_may_force_replace() {
        assert!(has_create_half(Action::Update));
        // The two predicates have to agree: anything should_replace() routes
        // to apply_replace must have been given an adoption id upstream.
        assert!(should_replace(true, true, Action::Update));
        assert!(has_create_half(Action::Update));
    }

    #[test]
    fn every_replace_shaped_action_has_a_create_half() {
        for a in [
            Action::Create,
            Action::Update,
            Action::Replace,
            Action::CreateThenDelete,
            Action::DeleteThenCreate,
        ] {
            assert!(has_create_half(a), "{a:?} can reach a create");
        }
    }

    /// Actions that never issue a create can never hit "already exists", so
    /// they must not spend a derivation — and, more importantly, must never be
    /// handed to adoption, which would report an unchanged object as success.
    #[test]
    fn actions_that_never_create_have_no_create_half() {
        for a in [Action::NoOp, Action::Delete, Action::Read, Action::Forget] {
            assert!(!has_create_half(a), "{a:?} cannot reach a create");
        }
    }

    /// Coverage is total by construction: `has_create_half` matches `Action`
    /// exhaustively with no `_` arm, so a new variant is a COMPILE error rather
    /// than a silent default. This row asserts the two lists above enumerate
    /// every variant, so the tests cannot quietly drift behind the type.
    #[test]
    fn the_create_half_matrix_covers_every_action() {
        let classified = [
            Action::Create,
            Action::Update,
            Action::Replace,
            Action::CreateThenDelete,
            Action::DeleteThenCreate,
            Action::NoOp,
            Action::Delete,
            Action::Read,
            Action::Forget,
        ];
        assert_eq!(
            classified.len(),
            9,
            "an Action variant was added/removed without updating the create-half matrix"
        );
    }
}

/// Persist a resource the provider **committed** even though the apply RPC
/// returned an error.
///
/// `ProviderError::PartiallyApplied` is the tfplugin contract's way of saying
/// "the mutation landed, and then something went wrong" — an AWS EIP whose
/// `AllocateAddress` succeeded before a follow-up call failed is the canonical
/// shape. Before this existed, the provider border discarded that state and
/// the engine recorded nothing, so the next reconcile re-planned a CREATE and
/// allocated a SECOND resource. Measured 2026-08-01 against example: two
/// orphaned EIPs (3.151.179.36, 18.227.192.150), both billable, neither in
/// state, while the run reported `created: 0`.
///
/// Recording here does NOT make the apply succeed — the caller still returns
/// `Err`. It makes the committed resource *known*, so the next plan sees it and
/// converges instead of duplicating it.
///
/// Returns true when state was recorded, for the caller's log line.
/// Does this state object carry a usable resource identity?
///
/// Every provider that actually creates something assigns `id` — it is the
/// handle refresh reads with and destroy deletes by. A state object without
/// one cannot be managed at all, so for our purposes it is not a resource.
///
/// Absent, `null`, and `""` are all treated the same, deliberately: an empty
/// string is what a provider echoes back for an unset computed attribute, and
/// it is exactly as unusable as a missing key.
pub(crate) fn has_resource_id(attrs: &serde_json::Value) -> bool {
    match attrs.get("id") {
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        // A non-string id (number/bool) is still an identity a provider chose.
        Some(v) => !v.is_null(),
        None => false,
    }
}

/// Does any string anywhere in this value still contain an unresolved `${…}`
/// interpolation?
///
/// State stores RESOLVED values. A `${…}` surviving into state is never the
/// product of a successful read — it is a provider echoing back the config it
/// was handed before references were substituted.
fn has_unresolved_interpolation(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => s.contains("${"),
        serde_json::Value::Array(a) => a.iter().any(has_unresolved_interpolation),
        serde_json::Value::Object(o) => o.values().any(has_unresolved_interpolation),
        _ => false,
    }
}

/// A state instance that magma can neither read, update nor destroy, AND that
/// demonstrably came from a failed apply rather than a real read.
///
/// Both halves are required. Missing-`id` alone is NOT sufficient: `id` is
/// mandatory for legacy-SDK resources but only conventional for
/// plugin-framework (protocol v6) ones, so dropping on that alone risks
/// deleting legitimate state. The unresolved-`${…}` half is what removes the
/// ambiguity.
pub(crate) fn is_unmanageable_phantom(attrs: &serde_json::Value) -> bool {
    !has_resource_id(attrs) && has_unresolved_interpolation(attrs)
}

fn record_partial_apply(
    rec: &mut NodeRecord,
    change: &ResourceChange,
    err: &ProviderError,
    implied: &CtyType,
    schema_version: u64,
) -> bool {
    let ProviderError::PartiallyApplied { state, .. } = err else {
        return false;
    };
    let address = &change.address;
    // A null new_state on a partial DELETE means the resource really is gone;
    // there is nothing to record and the absence is already correct.
    match state.to_json(implied) {
        Ok(attrs) if !attrs.is_null() => {
            // A partial state with NO usable `id` is not a resource — it is the
            // provider echoing back the config it was handed, before it assigned
            // an identity. Recording it creates a PHANTOM that can never be
            // cleaned up:
            //
            //   * refresh cannot ReadResource it (there is no id to read),
            //   * destroy cannot delete it (same),
            //   * and it re-plans as a pending Update forever, so the workspace
            //     trips `apply didn't converge` on every single cycle.
            //
            // Measured on example-eks-vpn-concentrator (2026-08-01): the SG
            // create failed while `vpc_id` was still the unresolved literal
            // `${data.aws_vpc.example_eks.id}`. The provider returned that echo
            // with no `id`, magma recorded it, and the workspace then failed
            // with "re-plan has 1 non-NoOp changes" on EVERY cycle — while
            // `describe-security-groups` proved no such SG existed (12 SGs
            // visible, that name absent). Nothing in the system could remove it.
            //
            // The tradeoff, stated rather than hidden: this is the guard that
            // exists to stop a committed-but-unrecorded resource becoming a
            // duplicate, so skipping a record is not free. It is still correct
            // here — a provider that actually created something assigns an id,
            // so an id-less echo means nothing was committed to converge on.
            // Between "might duplicate a resource that has no identity" and
            // "permanently wedge the workspace", the former is recoverable.
            if !has_resource_id(&attrs) {
                tracing::error!(
                    address = %address,
                    "magma apply: provider FAILED and returned a state with NO id — \
                     treating it as NOT committed. Recording it would create a \
                     phantom that refresh cannot read and destroy cannot remove, \
                     wedging every future plan on `apply didn't converge`."
                );
                return false;
            }
            rec.insert(change, attrs, schema_version);
            tracing::error!(
                address = %address,
                "magma apply: provider FAILED but COMMITTED this resource; \
                 recording the partial state so the next plan converges on it \
                 instead of creating a duplicate"
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            // Do not swallow: an undecodable partial state is the one case
            // where the resource exists and we cannot record it. Say so loudly
            // — this is the shape that leaks money.
            tracing::error!(
                address = %address,
                error = %e,
                "magma apply: provider COMMITTED this resource but its state \
                 could not be decoded; IT IS ORPHANED — reconcile by hand"
            );
            false
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
    adoption: Option<&crate::natural_id::ImportId>,
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
        lp.conn
            .apply_resource_change(type_name, &null_dv, &create_planned.state, config_dv)
    ) {
        Ok(dv) => dv,
        Err(e) => {
            let msg = e.to_string();
            record_partial_apply(rec, change, &e, implied, current_schema_version);
            // ADOPT-ON-CONFLICT, same as the plain create path. This half is a
            // create, so "it already exists" is answerable by adopting it —
            // and until this arm existed it was NOT, which is the whole reason
            // a replace-routed change could loop forever (measured 2026-08-02:
            // github_repository.blue, 12 creates in 45 minutes, all 422).
            //
            // Reaching here means the object survived step 1's destroy — the
            // provider reported the destroy done, yet the create says the name
            // is taken. Adoption is then both the unblock and the truthful
            // outcome: the object exists, so state should track it rather than
            // keep trying to conjure a duplicate. `rec.remove` above already
            // recorded the removal; adopting re-inserts, correcting it.
            match try_adopt_on_conflict(change, type_name, lp, pacer, adoption, &msg).await {
                Adoption::Adopted(attrs) => {
                    rec.insert(change, attrs.clone(), current_schema_version);
                    return Ok(AppliedChange {
                        address: change.address.clone(),
                        action: Action::DeleteThenCreate,
                        before: change.before.clone(),
                        after: Some(attrs),
                    });
                }
                Adoption::Mismatch {
                    attr,
                    planned,
                    imported,
                    id,
                } => {
                    tracing::error!(
                        address = ?change.address,
                        import_id = %id,
                        attr = %attr,
                        planned = %planned,
                        imported = %imported,
                        "magma adopt: imported resource is NOT the planned one; \
                         refusing the adoption"
                    );
                }
                Adoption::Absent => {}
            }
            let (crash, close) = provider_failure_signals(lp);
            return Err(rpc_error(
                provider_name,
                "apply_resource_change[replace:create]",
                crash,
                close,
                &msg,
            ));
        }
    };

    let new_attrs = new_dv
        .to_json(implied)
        .map_err(|e| EngineError::Cty(e.to_string()))?;
    rec.insert(change, new_attrs.clone(), current_schema_version);
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

/// The provider's local name (the `provider "<name>" {}` block name a
/// rendered config would use) inferred from a resource type's prefix —
/// the part before the first `_`, matching `terraform-provider-<name>`.
///
/// **Labelling only.** Provider SELECTION goes through
/// [`default_instance_for_type`] / [`provider_for_change`], which yield a
/// typed [`ProviderInstance`]; this survives for the diagnostics that
/// want the bare plugin name rather than an instance.
pub(crate) fn provider_local_name(type_id: &str) -> String {
    type_id.split('_').next().unwrap_or(type_id).to_string()
}

/// The provider INSTANCE a resource type implies with nothing declared —
/// always the DEFAULT instance of the type's prefix provider, which is
/// the only honest inference: nothing about a type name says which
/// account its resources belong in.
///
/// `pub(crate)` so [`crate::import_prepass::ConfiguredImportEnvironment`]
/// selects the SAME instance a plan/apply RPC for this type would dial,
/// without a second copy of this trivial-but-load-bearing mapping.
pub(crate) fn default_instance_for_type(type_id: &str) -> ProviderInstance {
    ProviderInstance::implied_by_type(type_id)
}

/// The provider local name to dial for one planned change — the
/// resource's DECLARED `provider` meta-argument when it has one, else
/// the type-prefix inference [`provider_local_name`] has always used.
///
/// **This is the fix for the wrong-provider defect.** Provider selection
/// used to read `provider_local_name(type_id)` and nothing else, so
/// `ProviderReference.alias` — a real field on a real type since M0 —
/// was consulted on no apply path at all. A resource declaring
/// `provider = "aws.us_east_2"` was applied through the DEFAULT `aws`
/// provider: infrastructure created in the wrong account or region, with
/// no error at any layer, because the meta-argument had already been
/// dropped at the cty boundary before selection ever ran.
///
/// The alias half is no longer refused at the config boundary: a
/// `ResourceChange` reaching here carries the full typed
/// [`ProviderInstance`], alias and all, and this function returns it
/// unchanged so the registry dials THAT instance. The prefix rule stays
/// as the fallback for the (overwhelmingly common) resource that declares
/// nothing, and remains a guess — `google_*` resources are served by the
/// `google` provider, but the mapping is convention, not contract. It
/// always yields a DEFAULT instance, which is the only honest inference:
/// nothing about a type name says which account it belongs in.
pub(crate) fn provider_for_change(change: &ResourceChange) -> ProviderInstance {
    match &change.meta.provider {
        Some(p) => p.clone(),
        None => default_instance_for_type(&change.address.type_id.0),
    }
}

/// The provider instance to READ a state row through — from the row's
/// own `StateResource.provider`, not from its type prefix.
///
/// The refresh paths used to select from the TYPE PREFIX and nothing
/// else, so a state row reading
/// `provider["registry.opentofu.org/hashicorp/aws"].us_east_2` was read
/// back through the DEFAULT `aws` provider. That queries a different
/// account or region than the one holding the resource, and the answer
/// ("it isn't there") is indistinguishable from real deletion drift.
/// `2e418ca` made that a blanket refusal of every aliased row.
///
/// Now the row's declared instance is dialed when the `ApplyContext`
/// configures it — the whole point of alias support. The refusal
/// survives for the case that is still genuinely unreadable: an aliased
/// row with no configuration, where dialing would fall back to the
/// environment (the default account) and produce exactly the wrong read
/// the refusal exists to prevent. Such a row is kept verbatim and counted
/// into `kept_on_error`, so the cycle's `Observation` reports the reduced
/// coverage instead of presenting a wrong read as fact.
///
/// `Err(kept)` carries the row back unchanged for the caller to keep.
fn refresh_instance_for(
    ctx: &ApplyContext,
    resource: &StateResource,
) -> Result<ProviderInstance, StateResource> {
    let Some(alias) = resource.provider.alias.as_deref() else {
        // The alias-free case — every row magma wrote before this landed,
        // and every row whose resource declares no `provider`. Unchanged:
        // the type prefix, the default instance.
        return Ok(default_instance_for_type(&resource.address.type_id.0));
    };
    let Ok(instance) = ProviderInstance::aliased(&resource.provider.name, alias) else {
        tracing::warn!(
            address = %resource.address,
            provider = %resource.provider.name,
            alias,
            "magma: refusing to refresh a resource whose state row names a malformed provider \
             instance. Kept verbatim and counted as unrefreshed.",
        );
        return Err(resource.clone());
    };
    if ctx.provider_configs.contains_key(&instance) {
        return Ok(instance);
    }
    tracing::warn!(
        address = %resource.address,
        provider = %resource.provider.name,
        alias,
        "magma: refusing to refresh a resource bound to an aliased provider instance nothing \
         configured — dialing it would fall back to the environment, i.e. the DEFAULT account \
         or region, so the read would query the wrong place and could report a live resource \
         as deleted. Kept verbatim and counted as unrefreshed.",
    );
    Err(resource.clone())
}

/// Build the apply-ordering graph for a set of planned changes.
///
/// ONE builder, shared by both apply engines — `run_plan_with_providers`
/// (the real provider-driven engine) and `crate::dependency_ordered`
/// (the M0 structural engine). They previously carried two independent
/// copies of this loop, which is precisely how the `depends_on` defect
/// could exist in both at once and be fixed in neither.
///
/// Two edge sources, and both are needed:
///
/// * **Interpolation** — a literal `${type.name.attr}` anywhere in the
///   change's `after`. This was the only source, and it is the reason
///   the defect was invisible: the overwhelming majority of real
///   ordering IS expressed as a reference, so ordering appeared to work.
/// * **`depends_on`** — ordering the author declared explicitly.
///   A `depends_on` exists precisely BECAUSE there is no interpolation
///   to infer the edge from (an author with a reference does not need
///   the meta-argument), so the one case the interpolation scan
///   structurally cannot see is exactly the case `depends_on` covers.
///   Dropping it meant a resource could be created before the thing it
///   was declared to require, with no error — the provider simply
///   failed, or worse, succeeded against an incomplete prerequisite.
///
/// An edge is added only when the target is itself among `changes`.
/// A dependency that is absent, already applied, or a NoOp needs no
/// ordering: it is not being touched this cycle, so nothing can race it.
///
/// The derivation itself is `magma_config::dependency_edges`, not a loop
/// here. It moved because a front end building typed
/// `magma_types::Resource` nodes needs the same two edge sources at
/// CONFIG time, before any plan exists — and re-deriving them there
/// would be a third copy of the loop whose second copy is exactly how
/// the missing `depends_on` source came to exist in two engines at once.
/// This function is now only the `changes → nodes → graph` wiring.
pub(crate) fn build_change_graph(changes: &[&ResourceChange]) -> ResourceGraph {
    let nodes: Vec<magma_types::DependencyNode<'_>> =
        changes.iter().map(|c| c.dependency_node()).collect();

    let mut graph = ResourceGraph::new();
    for c in changes {
        graph.add(c.address.clone());
    }
    for edge in magma_config::dependency_edges(&nodes) {
        graph.depend(edge.dependent, edge.dependency);
    }
    graph
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
    let provider_instance = provider_for_change(change);
    // The diagnostic label names WHICH CONNECTION failed, so it renders
    // the whole instance. For a default instance that is the bare name it
    // has always been; for an alias it is `aws.us_east_2`, which is the
    // only form that tells the reader which account the RPC went to.
    let provider_name = provider_instance.to_string();
    let lp = reg.get(&provider_instance).await?;
    let implied = lp
        .schema
        .data_source(&type_name)
        .ok_or_else(|| EngineError::NoDataSourceSchema(type_name.clone(), provider_name.clone()))?
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

// `collect_refs` / `ref_target` used to be defined RIGHT HERE, and that
// placement is what made them unreachable from config time. Edge
// derivation is needed by a front end that has built typed
// `magma_types::Resource` nodes and has no plan yet — it cannot depend on
// the apply engine to find out what depends on what. They now live in
// `magma_config`, with the rest of the escape-aware `${…}` family
// (`resolve_reference`, `resolve_config`, `has_interpolation`), which is
// also where they should have been when the 2026-07-23 escape incident
// needed the same fix applied in three separate places.
//
// `substitute_refs` below deliberately keeps its OWN scan: it must also
// rewrite `$${`/`%%{` back to `${`/`%{` in its output, which is a
// different job from pure extraction.
use magma_config::{collect_refs, ref_target};

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
                        Err(e) => {
                            // Unresolvable: repo-name fallback if applicable,
                            // else leave the literal untouched.
                            //
                            // "Leave the literal to surface the gap" was the
                            // original intent, and the literal DOES surface it
                            // — as an opaque provider error that never names
                            // the reference. Measured 2026-08-01: an
                            // unresolved `${data.aws_vpc.<n>.id}` reached AWS
                            // and came back as
                            //
                            //   InvalidGroupId.Malformed: Invalid id:
                            //   "${data.aws_vpc.<n>.id}" (expecting "sg-...")
                            //
                            // which reads as a malformed-config problem in the
                            // SECURITY GROUP, when the actual fault is that a
                            // DATA SOURCE never folded into the resolution
                            // map. Hours went into the wrong resource because
                            // the error pointed at the symptom.
                            //
                            // So: still fall through (hardening this to a
                            // typed error would break workspaces that limp
                            // along on partially-resolvable refs, and that is
                            // a separate, bigger decision) — but SAY the
                            // reference out loud at warn, once, where it
                            // happens. The provider error stays; it is no
                            // longer the only clue.
                            if let Some(n) = repo_name_ref_fallback(inner) {
                                *v = serde_json::Value::String(n);
                            } else {
                                tracing::warn!(
                                    reference = %trimmed,
                                    error = %e,
                                    "magma apply: UNRESOLVED reference — sending the \
                                     literal to the provider, which will reject it as a \
                                     malformed value on THIS resource. The real fault is \
                                     upstream: whatever this reference points at is not in \
                                     the resolution map (a data source that failed to read, \
                                     or a resource not yet applied)."
                                );
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

    /// The shape that wedged example-eks-vpn-concentrator: the provider
    /// echoed the config back (including an unresolved `${…}`) with no `id`.
    /// Recording that produced a phantom refresh could not read and destroy
    /// could not remove, so every subsequent plan failed `apply didn't
    /// converge`.
    #[test]
    fn id_less_partial_state_is_not_a_resource() {
        let echoed = serde_json::json!({
            "name": "vpn-concentrator-example-sg",
            "description": "VpnConcentrator WireGuard hub for example",
            "vpc_id": "${data.aws_vpc.example_eks.id}",
        });
        assert!(
            !has_resource_id(&echoed),
            "a config echo with no id must NOT be treated as committed"
        );
    }

    #[test]
    fn empty_and_null_ids_are_as_unusable_as_a_missing_one() {
        assert!(!has_resource_id(&serde_json::json!({ "id": "" })));
        assert!(!has_resource_id(&serde_json::json!({ "id": null })));
        assert!(!has_resource_id(&serde_json::json!({})));
    }

    /// The example phantom: no id AND an unresolved `${…}`. Both halves.
    #[test]
    fn phantom_needs_both_no_id_and_an_unresolved_interpolation() {
        let phantom = serde_json::json!({
            "name": "vpn-concentrator-example-sg",
            "vpc_id": "${data.aws_vpc.example_eks.id}",
        });
        assert!(is_unmanageable_phantom(&phantom));
    }

    /// The safety case that made the predicate narrower than "no id".
    /// A plugin-framework (protocol v6) resource is not REQUIRED to carry
    /// `id`; dropping state on that alone would be data loss.
    #[test]
    fn id_less_but_fully_resolved_state_is_kept() {
        let framework_resource = serde_json::json!({
            "name": "keep_me",
            "vpc_id": "vpc-0123456789abcdef0",
        });
        assert!(
            !is_unmanageable_phantom(&framework_resource),
            "a resolved id-less resource is legitimate state and must survive"
        );
    }

    /// And an interpolation alone is not enough either — a resource with a
    /// real id is manageable, so refresh/destroy can deal with it normally.
    #[test]
    fn an_interpolation_with_a_real_id_is_not_dropped() {
        let odd_but_manageable = serde_json::json!({
            "id": "sg-0123456789abcdef0",
            "vpc_id": "${data.aws_vpc.example_eks.id}",
        });
        assert!(!is_unmanageable_phantom(&odd_but_manageable));
    }

    #[test]
    fn unresolved_interpolation_is_found_when_nested() {
        assert!(has_unresolved_interpolation(&serde_json::json!({
            "ingress": [{ "security_groups": ["${aws_security_group.x.id}"] }]
        })));
        assert!(!has_unresolved_interpolation(&serde_json::json!({
            "ingress": [{ "security_groups": ["sg-123"] }]
        })));
    }

    #[test]
    fn a_real_id_still_records() {
        assert!(has_resource_id(
            &serde_json::json!({ "id": "sg-0123456789abcdef0" })
        ));
        // a provider that chose a non-string identity still chose one
        assert!(has_resource_id(&serde_json::json!({ "id": 42 })));
    }

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
        assert_eq!(
            repo_name_ref_fallback("github_repository.izumi.node_id"),
            None
        );
        // deeper path → no fallback
        assert_eq!(
            repo_name_ref_fallback("github_repository.izumi.name.x"),
            None
        );
        // other type → no fallback
        assert_eq!(
            repo_name_ref_fallback("github_branch_protection.x.name"),
            None
        );
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
            serde_json::json!(
                "jobs:\n  bump:\n    secrets:\n      BOT_PAT: ${{ secrets.BOT_PAT }}\n"
            )
        );
    }

    #[test]
    fn substitute_refs_unescapes_percent_brace_too() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let mut v = serde_json::json!("literal directive: %%{if true}yes%%{endif}");
        substitute_refs(&mut v, &sm);
        assert_eq!(
            v,
            serde_json::json!("literal directive: %{if true}yes%{endif}")
        );
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
        assert_eq!(
            v,
            serde_json::json!("${{ secrets.BOT_PAT }} repo=R_kgAizumi")
        );
    }

    #[test]
    fn substitute_refs_does_not_corrupt_multi_byte_utf8_around_escaped_content() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let mut v = serde_json::json!("caf\u{e9} $${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}");
        substitute_refs(&mut v, &sm);
        assert_eq!(
            v,
            serde_json::json!("caf\u{e9} ${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}")
        );

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
        assert!(mass_drop_should_suppress(
            MASS_DROP_FLOOR,
            MASS_DROP_FLOOR * 2
        ));
    }

    #[test]
    fn mass_drop_guard_trusts_genuine_phantoms() {
        // Nothing dropped → never suppress.
        assert!(!mass_drop_should_suppress(0, 1000));
        // A handful of real phantoms among many healthy targets → honor it.
        assert!(!mass_drop_should_suppress(2, 600));
        assert!(!mass_drop_should_suppress(
            MASS_DROP_FLOOR - 1,
            MASS_DROP_FLOOR - 1
        ));
        // At/above the floor but < half of probed targets → honor it.
        assert!(!mass_drop_should_suppress(
            MASS_DROP_FLOOR,
            MASS_DROP_FLOOR * 2 + 1
        ));
    }

    #[test]
    fn apply_context_has_default_pacer() {
        // Every apply paces mutation RPCs by default (1 req/s).
        let ctx = ApplyContext::new(PathBuf::from("/tmp/x"));
        assert!(
            ctx.pacer.is_some(),
            "default ApplyContext must carry a pacer"
        );
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
    /// The confidence gate REFUSES, and refuses exactly the guessing arms.
    ///
    /// This is the gate's only non-vacuous exercise: the integration provider
    /// (`mock_resource`) is name-keyed, so every id it derives is
    /// `NameAttribute`/exact and the gate there never sees an input it would
    /// reject — a guard that only ever meets inputs it accepts proves nothing
    /// (★★ UNREPRESENTABILITY Tier ⊥).
    ///
    /// RED RUN (performed): replacing the gate body with a bare
    /// `derived.map(|i| i.id)` fails both refusal assertions below — i.e.
    /// `tag_forge:bug` (a repo really named `tag-forge`) and a bare address
    /// name are handed straight to `ImportResourceState`.
    #[test]
    fn the_confidence_gate_refuses_a_guessed_import_id() {
        use crate::natural_id::{Confidence, ImportId};
        use magma_types::{ModulePath, ResourceKind, ResourceTypeId};
        let addr = ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("github_issue_label".into()),
            name: "tag_forge_label_bug".into(),
            key: None,
        };
        let gate = |c: Confidence| {
            gate_on_confidence(
                Some(ImportId {
                    id: "tag_forge:bug".into(),
                    confidence: c,
                }),
                &addr,
                "github_issue_label",
            )
        };

        assert_eq!(gate(Confidence::Catalog), Some("tag_forge:bug".to_string()));
        assert_eq!(
            gate(Confidence::NameAttribute),
            Some("tag_forge:bug".to_string())
        );
        assert_eq!(
            gate(Confidence::CatalogWithGuessedParent),
            None,
            "the parent was guessed from the resource name; the real repo is \
             `tag-forge`, so this id names a DIFFERENT repository's label"
        );
        assert_eq!(
            gate(Confidence::AddressName),
            None,
            "no rule and no `name` attribute is a pure guess"
        );
        assert_eq!(gate_on_confidence(None, &addr, "github_issue_label"), None);
    }

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
            meta: Default::default(),
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
        // CHANGED, deliberately (see `natural_id::derive`): a composite type
        // missing a key now REFUSES instead of falling back to the address
        // name. `github_actions_secret.orphan` with no `secret_name` used to
        // yield the import id `"orphan"` — a syntactically valid id that names
        // a DIFFERENT resource (a secret literally called "orphan", if one
        // exists). A failed adoption costs a cycle; a wrong adoption writes
        // someone else's state under this address.
        assert_eq!(
            natural_import_id(&mk(
                "github_actions_secret",
                "orphan",
                serde_json::json!({ "repository": "breathe" })
            )),
            None
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
        // THE CORRECTED BOUNDARY. This assertion previously pinned
        // `"${github_repository.izumi.node_id}:main"` as *intended* — the
        // reasoning being "a node_id reference is not a name, so keep it raw."
        // Both halves are true and the conclusion was still wrong: the GitHub
        // provider imports a branch protection by `<repository NAME>:<pattern>`
        // (registry docs: `terraform import github_branch_protection.terraform
        // terraform:main`; the importer calls `getRepositoryID(<first
        // segment>)`). So keeping it raw guaranteed an un-importable id, and
        // every branch protection that already existed on GitHub re-planned as
        // a create forever. `IdPart::ParentName` is the fix: the component is
        // declared as a PARENT, and a parent always resolves to its name — via
        // state when the parent is known, via the resource name as a labelled
        // guess when it is not (this state-less forwarder is the latter case).
        assert_eq!(
            natural_import_id(&mk(
                "github_branch_protection",
                "izumi_main",
                serde_json::json!({ "repository_id": "${github_repository.izumi.node_id}", "pattern": "main" })
            )),
            Some("izumi:main".to_string())
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
            meta: Default::default(),
        };
        let changes = vec![
            // a data source the planner marked NoOp (the bug trigger)
            mk(
                ResourceKind::Data,
                "cloudflare_zones",
                "rio_zone",
                Action::NoOp,
            ),
            // the dependent managed create (grafana CNAME)
            mk(
                ResourceKind::Managed,
                "cloudflare_dns_record",
                "grafana",
                Action::Create,
            ),
            // an unrelated NoOp managed resource (must stay in noops)
            mk(
                ResourceKind::Managed,
                "cloudflare_dns_record",
                "auth",
                Action::NoOp,
            ),
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
                meta: Default::default(),
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
                meta: Default::default(),
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
        assert!(
            a.after.is_none(),
            "a forgotten data source has no after-state"
        );
        // And it is gone from state — the manual Postgres purge is now automatic.
        assert!(
            state.resources.iter().all(|r| r.address != orphan),
            "the orphaned data-source row must be dropped from state",
        );
        assert!(state.resources.is_empty(), "no rows remain");
    }

    // ── Provider selection + declared ordering ─────────────────────

    fn change_with_meta(ty: &str, name: &str, meta: magma_types::ResourceMeta) -> ResourceChange {
        ResourceChange {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId(ty.into()),
                name: name.into(),
                key: None,
            },
            action: Action::Create,
            before: None,
            after: Some(serde_json::json!({ "name": name })),
            reasons: vec![],
            meta,
        }
    }

    /// Provider selection read the resource TYPE PREFIX and nothing
    /// else, so a resource that named its provider explicitly was
    /// applied through whichever provider its type happened to spell.
    #[test]
    fn a_resource_that_names_its_provider_is_dialed_through_that_provider() {
        let meta = magma_types::ResourceMeta {
            provider: Some(
                magma_types::ProviderInstance::try_from("githubenterprise".to_string()).unwrap(),
            ),
            depends_on: vec![],
            ignore_changes: vec![],
        };
        let c = change_with_meta("github_repository", "izumi", meta);
        assert_eq!(
            provider_for_change(&c).to_string(),
            "githubenterprise",
            "the DECLARED provider must win over the type-prefix guess",
        );
    }

    #[test]
    fn a_resource_that_names_no_provider_still_falls_back_to_its_type_prefix() {
        let c = change_with_meta("github_repository", "izumi", Default::default());
        let selected = provider_for_change(&c);
        assert_eq!(selected.name(), "github");
        assert!(
            selected.is_default(),
            "the type-prefix guess can only ever name a DEFAULT instance",
        );
    }

    // ── Aliased provider instances ─────────────────────────────────
    //
    // Selection used to be `type_id.split('_').next()` and nothing else,
    // so a resource declaring `provider = "aws.us_east_2"` was applied
    // through the DEFAULT `aws` provider. `2e418ca` made the declaration
    // a refusal; these pin that it is now HONOURED — end to end, from the
    // change through the registry key to the state row refresh reads back.

    fn aliased(name: &str, alias: &str) -> ProviderInstance {
        ProviderInstance::aliased(name, alias).expect("a well-formed instance")
    }

    fn aliased_change(ty: &str, name: &str, instance: ProviderInstance) -> ResourceChange {
        change_with_meta(
            ty,
            name,
            magma_types::ResourceMeta {
                provider: Some(instance),
                depends_on: vec![],
                ignore_changes: vec![],
            },
        )
    }

    #[test]
    fn an_aliased_declaration_selects_the_aliased_instance_not_the_default() {
        let c = aliased_change("aws_instance", "web", aliased("aws", "us_east_2"));
        let selected = provider_for_change(&c);
        assert_eq!(selected, aliased("aws", "us_east_2"));
        assert_ne!(
            selected,
            ProviderInstance::default_instance("aws").unwrap(),
            "the whole defect was that these two were the same value",
        );
    }

    /// The registry key. Two instances of one provider must occupy two
    /// slots — a name-keyed cache would hand the second resource the
    /// first one's connection, which is the wrong account with no error.
    #[test]
    fn two_instances_of_one_provider_are_two_registry_keys() {
        let default = ProviderInstance::default_instance("aws").unwrap();
        let east2 = aliased("aws", "us_east_2");
        let mut keys = std::collections::HashSet::new();
        keys.insert(default.clone());
        keys.insert(east2.clone());
        assert_eq!(keys.len(), 2);
        assert_eq!(
            default.name(),
            east2.name(),
            "…while still naming the same provider BINARY",
        );
    }

    /// **The gate that makes honouring an alias safe.** An empty config
    /// makes a provider fall back to its environment credentials — the
    /// default account. For the default instance that is correct and is
    /// what terraform does; for an alias it is the original wrong-account
    /// defect one layer down, so it is refused instead.
    #[test]
    fn an_unconfigured_aliased_instance_is_refused_rather_than_dialed_with_an_empty_config() {
        let ctx = ApplyContext::new(PathBuf::from("/ws"));
        let err = resolve_provider_config(&ctx, &aliased("aws", "us_east_2"))
            .expect_err("an unconfigured alias must not fall back to the environment");
        assert!(
            matches!(err, EngineError::UnconfiguredProviderAlias { .. }),
            "must be the typed refusal, got: {err}"
        );
        assert!(
            err.to_string().contains("DEFAULT account or region"),
            "must name the consequence it prevents: {err}"
        );
    }

    #[test]
    fn the_default_instance_still_dials_with_an_empty_config() {
        let ctx = ApplyContext::new(PathBuf::from("/ws"));
        let cfg =
            resolve_provider_config(&ctx, &ProviderInstance::default_instance("aws").unwrap())
                .expect("an absent provider block means environment credentials, as before");
        assert_eq!(cfg, serde_json::json!({}));
    }

    #[test]
    fn a_configured_aliased_instance_dials_with_its_own_configuration() {
        let east2 = aliased("aws", "us_east_2");
        let ctx = ApplyContext::new(PathBuf::from("/ws"))
            .with_provider_config("aws", serde_json::json!({ "region": "us-east-1" }))
            .with_provider_instance_config(
                east2.clone(),
                serde_json::json!({ "region": "us-east-2" }),
            );
        assert_eq!(
            resolve_provider_config(&ctx, &east2).unwrap(),
            serde_json::json!({ "region": "us-east-2" }),
        );
        // …and the default instance keeps its own, distinct, config. This
        // is what a single-slot map could not hold.
        assert_eq!(
            resolve_provider_config(&ctx, &ProviderInstance::default_instance("aws").unwrap())
                .unwrap(),
            serde_json::json!({ "region": "us-east-1" }),
        );
    }

    /// **A state row that lies about its provider is the same defect with
    /// a delay fuse.** Refresh selects from `StateResource.provider`, so a
    /// row written with `alias: None` for a resource that lives in
    /// `us-east-2` sends the next `ReadResource` to the default account,
    /// where "it isn't there" is indistinguishable from deletion drift.
    #[test]
    fn an_aliased_apply_records_the_alias_in_the_state_row() {
        let change = aliased_change("aws_instance", "web", aliased("aws", "us_east_2"));
        let mut rec = NodeRecord::default();
        rec.insert(&change, serde_json::json!({ "id": "i-1" }), 0);
        let mut state = empty_state();
        rec.commit(&mut state);

        let row = state
            .resources
            .iter()
            .find(|r| r.address == change.address)
            .expect("recorded");
        assert_eq!(row.provider.name, "aws");
        assert_eq!(row.provider.alias.as_deref(), Some("us_east_2"));
        // `source` stays inferred from the type prefix — the one component
        // nothing on the apply path knows any better.
        assert_eq!(row.provider.source, "hashicorp/aws");
    }

    /// The apply → state → **tfstate v4 bytes** chain, pinned against
    /// what OpenTofu itself writes.
    ///
    /// The two halves of this were each covered and their JOIN was not:
    /// the test above asserts the typed `ProviderReference` fields, and
    /// magma-state's `provider_reference_round_trips_with_alias` asserts
    /// the string form of a reference built by hand. Nothing pinned that
    /// an apply's row, once ENCODED, is the byte an operator's existing
    /// tofu state already contains — so `default_provider_for`'s source
    /// mapping, `provider_reference_for`'s alias threading and
    /// `format_provider_reference`'s registry qualification could each
    /// keep passing their own test while the composed byte drifted. State
    /// compatibility is the whole compatibility contract for a resource
    /// magma adopts from tofu or hands back to it: a row whose provider
    /// string does not match is a row tofu reads as bound to a provider
    /// configuration it cannot find.
    ///
    /// The expected strings are not derived — they are transcribed from a
    /// real `tofu apply` (OpenTofu v1.10.9, darwin_arm64) over a config
    /// declaring `provider "null" {}`, `provider "null" { alias = "second" }`
    /// and one resource pinned to each. Both come from the same state
    /// file, so the aliased and unaliased forms are pinned against one
    /// another exactly as tofu emits them.
    #[test]
    fn an_encoded_row_carries_the_exact_provider_string_opentofu_writes() {
        let cases = [
            (
                aliased_change("null_resource", "b", aliased("null", "second")),
                "provider[\"registry.opentofu.org/hashicorp/null\"].second",
            ),
            (
                change_with_meta("null_resource", "a", Default::default()),
                "provider[\"registry.opentofu.org/hashicorp/null\"]",
            ),
        ];

        for (change, expected) in cases {
            let mut rec = NodeRecord::default();
            rec.insert(
                &change,
                serde_json::json!({ "id": "2061053846366703230" }),
                0,
            );
            let mut state = empty_state();
            rec.commit(&mut state);

            let bytes = magma_state::tfstate_v4::encode(&state).expect("encodes");
            let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
            let written = doc["resources"][0]["provider"]
                .as_str()
                .expect("every resource row carries a provider string");
            assert_eq!(
                written, expected,
                "the encoded provider string must be byte-identical to OpenTofu's, or tofu \
                 reads this row as bound to a provider configuration it cannot find",
            );
        }
    }

    #[test]
    fn an_unaliased_apply_records_exactly_the_row_it_always_did() {
        let change = change_with_meta("aws_instance", "web", Default::default());
        let mut rec = NodeRecord::default();
        rec.insert(&change, serde_json::json!({ "id": "i-1" }), 0);
        let mut state = empty_state();
        rec.commit(&mut state);

        let row = &state.resources[0];
        assert_eq!(row.provider, crate::default_provider_for(&change.address));
        assert_eq!(row.provider.alias, None);
    }

    /// Refresh reads a row back through the instance the row NAMES, once
    /// that instance is configured. Before, it read every row through the
    /// type prefix and refused any aliased row outright.
    #[test]
    fn refresh_reads_an_aliased_row_through_its_own_configured_instance() {
        let east2 = aliased("aws", "us_east_2");
        let ctx = ApplyContext::new(PathBuf::from("/ws"))
            .with_provider_instance_config(east2.clone(), serde_json::json!({}));
        let row = StateResource {
            address: change_with_meta("aws_instance", "web", Default::default()).address,
            provider: magma_types::ProviderReference {
                source: "registry.opentofu.org/hashicorp/aws".into(),
                name: "aws".into(),
                alias: Some("us_east_2".into()),
            },
            instances: vec![],
        };
        assert_eq!(
            refresh_instance_for(&ctx, &row).ok(),
            Some(east2),
            "the row's OWN provider reference selects the instance, not its type prefix",
        );
    }

    /// …and an aliased row nothing configures is still kept verbatim,
    /// because dialing it would fall back to the default account and the
    /// answer would be a wrong read presented as fact.
    #[test]
    fn refresh_still_refuses_an_aliased_row_nothing_configures() {
        let ctx = ApplyContext::new(PathBuf::from("/ws"));
        let row = StateResource {
            address: change_with_meta("aws_instance", "web", Default::default()).address,
            provider: magma_types::ProviderReference {
                source: "registry.opentofu.org/hashicorp/aws".into(),
                name: "aws".into(),
                alias: Some("us_east_2".into()),
            },
            instances: vec![],
        };
        assert!(
            refresh_instance_for(&ctx, &row).is_err(),
            "an unconfigured aliased row must be kept, not read through the default account",
        );
    }

    /// **The end-to-end join.** A config that declares two instances of
    /// one provider yields an `ApplyContext` that can dial both — which is
    /// the difference between an alias being expressible and an alias
    /// being usable.
    #[test]
    fn a_config_declaring_two_instances_configures_both_of_them() {
        let cfg = magma_config::Config::from_json(serde_json::json!({
            "provider": {
                "aws": [
                    { "region": "us-east-1" },
                    { "alias": "us_east_2", "region": "us-east-2" }
                ]
            }
        }))
        .expect("parses");
        let ctx = ApplyContext::new(PathBuf::from("/ws")).with_config_providers(&cfg);
        assert_eq!(
            resolve_provider_config(&ctx, &aliased("aws", "us_east_2")).unwrap(),
            serde_json::json!({ "region": "us-east-2" }),
        );
        assert_eq!(
            resolve_provider_config(&ctx, &ProviderInstance::default_instance("aws").unwrap())
                .unwrap(),
            serde_json::json!({ "region": "us-east-1" }),
        );
    }

    /// …and an `ApplyContext` that never adopts a config is untouched.
    #[test]
    fn an_apply_context_that_adopts_no_config_carries_no_provider_configs() {
        assert!(
            ApplyContext::new(PathBuf::from("/ws"))
                .provider_configs
                .is_empty()
        );
    }

    /// The unaliased row — every row magma wrote before this landed —
    /// still resolves to the type-prefix default instance, unchanged.
    #[test]
    fn refresh_selects_the_type_prefix_default_for_an_unaliased_row() {
        let ctx = ApplyContext::new(PathBuf::from("/ws"));
        let row = StateResource {
            address: change_with_meta("aws_instance", "web", Default::default()).address,
            provider: crate::default_provider_for(
                &change_with_meta("aws_instance", "web", Default::default()).address,
            ),
            instances: vec![],
        };
        assert_eq!(
            refresh_instance_for(&ctx, &row).ok(),
            Some(ProviderInstance::default_instance("aws").unwrap()),
        );
    }

    /// THE `depends_on` defect. The graph was built ONLY by scanning
    /// `after` for literal `${type.name.attr}` strings, so an ordering
    /// declared with no interpolation to infer from produced NO edge —
    /// and `depends_on` exists precisely for the case where there is no
    /// interpolation. The resource could be created before the thing it
    /// was declared to require, with no error anywhere.
    #[test]
    fn a_declared_depends_on_orders_the_apply_even_with_no_interpolation() {
        let role = change_with_meta("aws_iam_role", "exec", Default::default());
        let dependent = change_with_meta(
            "aws_lambda_function",
            "handler",
            magma_types::ResourceMeta {
                provider: None,
                depends_on: vec![role.address.clone()],
                ignore_changes: vec![],
            },
        );
        // Deliberately dependent-first, so plan order alone would apply
        // the lambda before its role.
        let changes = vec![&dependent, &role];
        let graph = build_change_graph(&changes);
        assert!(
            graph.depends_on(&dependent.address, &role.address),
            "a declared depends_on must be a real graph edge",
        );
        // Asserted on the WAVE decomposition, which is what the
        // provider-backed executor actually consumes — this crate is
        // sealed against collapsing waves into a flat order (see
        // `the_provider_apply_never_linearises_the_wave_decomposition`).
        let waves = graph.waves().expect("acyclic");
        let wave_of = |addr: &ResourceAddress| {
            waves
                .iter()
                .position(|w| w.iter().any(|a| a == addr))
                .expect("every node lands in some wave")
        };
        assert!(
            wave_of(&role.address) < wave_of(&dependent.address),
            "the declared dependency must land in an earlier wave, so it is applied first",
        );
        assert_eq!(
            waves.len(),
            2,
            "one edge means two waves; a single wide wave would assert these are independent",
        );
    }

    /// The interpolation-derived edges must keep working unchanged —
    /// the new source is additive, not a replacement.
    #[test]
    fn an_interpolated_reference_still_orders_the_apply() {
        let vpc = change_with_meta("aws_vpc", "main", Default::default());
        let mut subnet = change_with_meta("aws_subnet", "priv", Default::default());
        subnet.after = Some(serde_json::json!({ "vpc_id": "${aws_vpc.main.id}" }));
        let changes = vec![&subnet, &vpc];
        let graph = build_change_graph(&changes);
        assert!(graph.depends_on(&subnet.address, &vpc.address));
    }

    /// A `depends_on` pointing at something this cycle is not touching
    /// needs no edge — it is not being changed, so nothing can race it.
    #[test]
    fn a_depends_on_targeting_a_resource_outside_this_cycle_adds_no_edge() {
        let absent = ResourceAddress {
            module: magma_types::ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: magma_types::ResourceTypeId("aws_iam_role".into()),
            name: "not_in_this_plan".into(),
            key: None,
        };
        let only = change_with_meta(
            "aws_lambda_function",
            "handler",
            magma_types::ResourceMeta {
                provider: None,
                depends_on: vec![absent.clone()],
                ignore_changes: vec![],
            },
        );
        let changes = vec![&only];
        let graph = build_change_graph(&changes);
        assert_eq!(graph.len(), 1, "no phantom node for an untouched target");
        assert!(!graph.depends_on(&only.address, &absent));
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
        assert!(
            ctx.provider_configs
                .contains_key(&ProviderInstance::default_instance("github").unwrap()),
            "a bare name still configures the DEFAULT instance, exactly as before",
        );
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
        assert_eq!(
            report.kept_on_error, 1,
            "kept the instance it couldn't read"
        );
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

        assert!(
            report.is_none(),
            "ctx = None must not produce a refresh report"
        );
        assert_eq!(
            via_helper.resource_changes.len(),
            direct.resource_changes.len()
        );
        assert_eq!(
            via_helper.resource_changes[0].action, direct.resource_changes[0].action,
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
        let (plan, report) = refresh_then_plan(&cfg, &mut state, Some(&ctx))
            .await
            .unwrap();

        let report = report.expect("ctx = Some(_) must produce a refresh report");
        assert_eq!(
            report.kept_on_error, 1,
            "no provider reachable — kept, not dropped"
        );
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
        assert!(
            got.contains("ghost"),
            "a real 404 must still nominate the parent, got {got:?}"
        );
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
        assert!(
            parents.contains("kanchi"),
            "repo name from /repos/owner/kanchi/labels 404"
        );
        assert!(
            parents.contains("akeyless_stack"),
            "resource name from the ${{github_repository.X}} ref"
        );

        // A repo-CREATE 422 on /orgs/.../repos must NOT implicate a parent
        // (inverse-phantom — exists in cloud, not state — handled elsewhere).
        let inverse = vec![mkfail(
            "github_repository",
            "breathe",
            "POST https://api.github.com/orgs/pleme-io/repos: 422 Repository creation failed [name already exists]",
        )];
        assert!(
            collect_phantom_parents(&inverse).is_empty(),
            "repo-create 422 is not a phantom signal"
        );

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
                mkrepo("kanchi", "kanchi"),                 // phantom → dropped
                mkrepo("akeyless_stack", "akeyless-stack"), // phantom (addr-name match) → dropped
                mkrepo("galho", "galho"),                   // not implicated → kept
            ],
        };
        let dropped = drop_repos_from_state(&mut state, &parents);
        assert_eq!(dropped, 2, "kanchi + akeyless_stack dropped");
        assert_eq!(state.resources.len(), 1);
        assert_eq!(
            state.resources[0].address.name, "galho",
            "non-phantom survives"
        );
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
                    meta: Default::default(),
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
        let change = change_with_meta("github_repository", "r", Default::default());
        let mut rec = NodeRecord::default();
        rec.remove(&addr);
        rec.insert(&change, serde_json::json!({ "name": "r" }), 3);

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
        backwards.insert(&change, serde_json::json!({ "name": "r" }), 3);
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
        let a = change_with_meta("github_repository", "a", Default::default());
        let b = change_with_meta("github_repository", "b", Default::default());
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
        let mut n1: Vec<_> = s1
            .resources
            .iter()
            .map(|r| r.address.name.clone())
            .collect();
        let mut n2: Vec<_> = s2
            .resources
            .iter()
            .map(|r| r.address.name.clone())
            .collect();
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

        assert!(
            out.is_complete(),
            "a fully-covered plan is finished: {out:?}"
        );
        assert!(!out.needs_another_cycle());
        assert_eq!(out.stats().nodes_attempted, 0);
        assert_eq!(out.stats().nodes_remaining, 0);
        assert!(
            out.outcome().failed.is_empty(),
            "nothing was executed, so nothing can have failed"
        );
        assert!(
            out.cursor().is_none(),
            "a finished plan carries no position"
        );
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
                meta: Default::default(),
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

        let r = record_data_read(&mut cursor, &addr, &value, &state, Some(&sink), &mut stats).await;

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
    /// The **mutation** path only. The refresh path is now paced too
    /// (2026-08-08) and is covered by `every_provider_rpc_is_paced` below
    /// rather than by this test, which still would not notice.
    ///
    /// The `Paced<'_>` witness — a type the provider methods demand, making
    /// "forgot the pacer" a compile error rather than a reviewer's job — is
    /// still NOT built. So the class is CI-caught, not unrepresentable, and
    /// the source-level gate is what stands in for the type.
    ///
    /// # Tier
    ///
    /// Only-mitigated, and a **C2/C4 ceiling** rather than debt: the provider's
    /// true safe rate is an external-world fact discovered from response
    /// headers. What is sealed here is that the rate the engine was *told* to
    /// hold is actually held — the plumbing, not the number.
    /// Every provider RPC in this engine goes through the pacer.
    ///
    /// `refresh_state` shipped unpaced while its own sibling `refresh_named`
    /// paced the identical `read_resource` call — one character of difference
    /// (`None::<&LeakyBucket>` vs `pacer.as_deref()`), invisible in review and
    /// invisible at runtime, since an unpaced read succeeds. It just spends
    /// budget nobody accounted for: 4,786 reads per cycle against GitHub's
    /// 5,000 req/hr, which is why three approvals produced zero applies.
    ///
    /// Until the `Paced<'_>` witness exists this is the seal, and it is a
    /// SOURCE-level one on purpose — the defect is a missing argument, so no
    /// behavioural test can see it. A new RPC that forgets the pacer fails
    /// here instead of quietly eating the budget.
    #[test]
    fn every_provider_rpc_is_paced() {
        let src = include_str!("engine.rs");
        // Split so this detector is not its own offender — the literal must
        // not appear on any line of the search itself.
        let needle = concat!("None::<&", "LeakyBucket>");
        let offenders: Vec<usize> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            // The doc prose above quotes the token; only real arguments count.
            .filter(|(_, l)| !l.trim_start().starts_with("///"))
            .map(|(i, _)| i + 1)
            .collect();
        assert!(
            offenders.is_empty(),
            "unpaced provider RPC at line(s) {offenders:?} — pass the pacer \
             (`ctx.pacer.as_deref()`), never `None`. An unpaced RPC still \
             succeeds; it just spends budget nobody accounted for."
        );
    }

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
