//! magma-apply::import_prepass — adopt pre-existing resources into the
//! working state BEFORE the create-plan runs.
//!
//! This is the apply-side keystone that closes the
//! "create-plan 422s already-exists" failure class. The operator
//! hands magma per-resource `ImportDirectives`:
//!
//!   * `explicit` — `spec.importHints`: address → provider-specific id.
//!   * `auto_on_conflict` — `importPolicy.autoOnConflict`: when a
//!     create is rejected as already-exists, retry it as an import
//!     using the resource's natural id.
//!
//! The prepass calls the provider's `ImportResourceState` RPC for each
//! directive, decodes the returned state, and absorbs it into the
//! working `State` as a `Ready` instance — so the SUBSEQUENT plan sees
//! the resource as existing (NoOp / Update), not Create.
//!
//! Contract (per the org ★★ MAGMA-NATIVE rules + TYPED-SPEC triplet):
//!
//!   * **Order-correct** — the prepass runs BEFORE plan. The whole
//!     point is that plan observes the absorbed state.
//!   * **Idempotent** — importing an address already present in state
//!     is a NoOp; no RPC, no duplicate.
//!   * **Per-resource failure isolation** — a failed import (bad id,
//!     provider error, type doesn't support import) is a typed
//!     `FailedImport` on THAT address. It never aborts the prepass or
//!     the apply; the resource simply stays un-absorbed and the plan
//!     proceeds (it will re-propose Create, and the operator sees the
//!     failure in the typed receipt).
//!
//! The side-effecting RPC is abstracted behind the `ImportEnvironment`
//! trait — the testability contract. The real impl
//! (`PluginImportEnvironment`) drives `magma_plugin::import_resource_state`
//! over a dialed channel; tests mock it.

use std::collections::HashMap;

use async_trait::async_trait;
use magma_types::{
    ImportDirectives, ImportTarget, ImportedInstance, InstanceStatus, ModulePath, ProviderInstance,
    ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId, State, StateInstance,
    StateResource,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ImportPrepassError {
    #[error("import environment error for {address}: {reason}")]
    Environment { address: String, reason: String },
    #[error("malformed import address {0:?}: expected `type.name`")]
    MalformedAddress(String),
}

// ── Per-address import receipt ─────────────────────────────────────

/// One resource the prepass adopted into state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedAddress {
    /// Canonical address string (`cloudflare_zone.quero_cloud`).
    pub address: String,
    /// The provider-specific id used to import it.
    pub id: String,
    /// Whether the absorb actually changed state. `false` ⇒ the
    /// resource was already present (idempotent NoOp — no RPC ran).
    pub absorbed: bool,
}

/// One import that failed. Mirrors `magma_apply::FailedChange` shape but
/// scoped to the prepass; never aborts the apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedImport {
    /// Canonical address string.
    pub address: String,
    /// The provider-specific id the prepass attempted.
    pub id: String,
    /// Why the import failed (provider rejected, bad id, RPC error).
    pub reason: String,
}

/// The typed receipt of the import prepass — what was adopted, what
/// failed. Threads into the apply outcome / bundle so operators see
/// import results mechanically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPrepassOutcome {
    pub imported: Vec<ImportedAddress>,
    pub failed: Vec<FailedImport>,
}

impl ImportPrepassOutcome {
    /// True iff every attempted import succeeded (or there was nothing
    /// to import). A non-empty `failed` list does NOT block apply — the
    /// failed addresses simply re-plan as Create.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty()
    }

    /// How many addresses were newly absorbed into state.
    #[must_use]
    pub fn newly_absorbed(&self) -> usize {
        self.imported.iter().filter(|i| i.absorbed).count()
    }
}

// ── The testability seam: ImportEnvironment ────────────────────────

/// The side-effecting surface the prepass drives — exactly one method:
/// "given a type_name + id, return the live resource's imported state".
/// The real impl drives the provider gRPC; tests mock it. This is the
/// Environment trait the TYPED-SPEC triplet mandates so the prepass is
/// testable without a real provider subprocess / network.
#[async_trait]
pub trait ImportEnvironment: Send + Sync {
    /// Call the provider's `ImportResourceState` for `(type_name, id)`,
    /// issued to `provider` — the INSTANCE that holds the resource.
    ///
    /// The instance is a parameter rather than something the
    /// implementation infers, because `ImportResourceState` is answered
    /// by whichever configured instance receives it. Inferring it from
    /// the type prefix — the only thing available before this — always
    /// yields the DEFAULT instance, so a resource living in a second
    /// account could not be imported at all: the RPC asked an account
    /// that never held it, and "not found" is what came back. The worse
    /// outcome is the silent one, where a resource in the default
    /// account answers to the same id and gets adopted into an address
    /// that meant something else.
    ///
    /// Callers that have no instance to name pass
    /// `ProviderInstance::implied_by_type(type_name)`, which is exactly
    /// the old behaviour written down.
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
        provider: &ProviderInstance,
    ) -> Result<Vec<ImportedInstance>, String>;
}

// ── The prepass ────────────────────────────────────────────────────

/// Run the explicit-hint half of the import prepass against `state`,
/// mutating it in place. For each `(address, id)` in
/// `directives.explicit`, if the address is NOT already present in
/// state, call the environment's `import_resource_state` and absorb the
/// result. Idempotent + per-resource-failure-isolated.
///
/// `auto_on_conflict` is handled separately by
/// [`import_on_conflict`] — it's driven from the apply loop when a
/// create is rejected as already-exists, because it needs the natural
/// id derived from the planned resource, not an operator-supplied one.
///
/// Returns the typed receipt. Never returns `Err` for a per-resource
/// import failure — those land in `outcome.failed`. The outer `Result`
/// is reserved for structural errors (a malformed address string an
/// operator typo'd).
pub async fn run_explicit_prepass<E: ImportEnvironment>(
    env: &E,
    directives: &ImportDirectives,
    state: &mut State,
) -> Result<ImportPrepassOutcome, ImportPrepassError> {
    let mut outcome = ImportPrepassOutcome::default();
    if directives.explicit.is_empty() {
        return Ok(outcome);
    }

    // Deterministic order: sort addresses so the receipt + any
    // attestation over it is stable across runs.
    let mut entries: Vec<(&String, &ImportTarget)> = directives.explicit.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    for (address, target) in entries {
        let parsed = parse_address(address)?;
        let id = target.id();
        // The instance the hint pins the import to, or the default one
        // its type implies — which is what every hint meant before a
        // hint could name an instance, so an un-pinned hint behaves
        // exactly as it always has.
        let instance = target
            .provider()
            .cloned()
            .unwrap_or_else(|| ProviderInstance::implied_by_type(&parsed.type_id.0));

        // Idempotency: already in state ⇒ NoOp, no RPC.
        if state_contains(state, &parsed) {
            debug!(%address, "import prepass: already in state, skipping (idempotent NoOp)");
            outcome.imported.push(ImportedAddress {
                address: address.clone(),
                id: id.to_string(),
                absorbed: false,
            });
            continue;
        }

        match env
            .import_resource_state(&parsed.type_id.0, id, &instance)
            .await
        {
            Ok(instances) => {
                absorb(state, &parsed, &instances, &instance);
                debug!(%address, %id, count = instances.len(), "import prepass: absorbed");
                outcome.imported.push(ImportedAddress {
                    address: address.clone(),
                    id: id.to_string(),
                    absorbed: true,
                });
            }
            Err(reason) => {
                // Per-resource failure isolation: log + record, never
                // abort. The address stays un-absorbed; plan re-proposes
                // Create and the operator sees the failure in the receipt.
                warn!(%address, %id, %reason, "import prepass: import failed (resource stays un-absorbed)");
                outcome.failed.push(FailedImport {
                    address: address.clone(),
                    id: id.to_string(),
                    reason,
                });
            }
        }
    }

    Ok(outcome)
}

/// The `auto_on_conflict` arm: a create was rejected as already-exists;
/// retry it as an import using the resource's natural `id`. Absorbs the
/// imported state into `state` so the resource becomes managed. Returns
/// `Ok(true)` if the import succeeded + was absorbed, `Ok(false)` if the
/// address was already present (idempotent), or `Err(reason)` if the
/// import itself failed (the caller records a typed FailedChange).
///
/// `natural_id` is the id magma would have created the resource under —
/// for `github_repository` it's the repo name; the apply loop derives it
/// from the planned `after` attributes.
/// `provider` is the instance the conflicting CREATE was routed to —
/// `magma_apply::engine::provider_for_change` for the change that just
/// failed. It must be that same instance and not the type-prefix
/// default: the create raced a resource that already exists IN THAT
/// INSTANCE, so adopting through any other one either finds nothing or
/// finds a different resource.
pub async fn import_on_conflict<E: ImportEnvironment>(
    env: &E,
    address: &ResourceAddress,
    natural_id: &str,
    state: &mut State,
    provider: &ProviderInstance,
) -> Result<bool, String> {
    if state_contains(state, address) {
        return Ok(false);
    }
    let instances = env
        .import_resource_state(&address.type_id.0, natural_id, provider)
        .await?;
    absorb(state, address, &instances, provider);
    Ok(true)
}

// ── Real environment: provider gRPC over a dialed channel ──────────

/// The production `ImportEnvironment` — drives the real provider
/// `ImportResourceState` RPC via `magma_plugin::import_resource_state`
/// over a dialed `magma_plugin::H2Channel`. The channel comes from a
/// spawned `magma_plugin::Plugin::dial()` — the same direct-h2 transport
/// the engine's reactive on-conflict import rides (go-plugin providers
/// hang on tonic's `Channel`; the custom `H2Channel` is the fix). This
/// is the one sanctioned filesystem reach (loading + exec'ing the
/// provider plugin binary) per the ★★ MAGMA-NATIVE EXECUTION directive —
/// everything else stays in memory.
pub struct PluginImportEnvironment {
    channel: magma_plugin::H2Channel,
}

impl PluginImportEnvironment {
    /// Wrap a dialed provider channel. Cheap to clone — the channel is
    /// a multiplexed gRPC handle.
    #[must_use]
    pub fn new(channel: magma_plugin::H2Channel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl ImportEnvironment for PluginImportEnvironment {
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
        provider: &ProviderInstance,
    ) -> Result<Vec<ImportedInstance>, String> {
        // This environment is handed ONE already-dialed channel and has
        // no way to reach a different instance — there is no registry
        // here, no `ApplyContext`, nothing to select from. So an aliased
        // instance is refused rather than issued down whichever channel
        // happened to be passed in, which would be an import against an
        // unknown account presented as success.
        //
        // `ConfiguredImportEnvironment` is the one that CAN honour an
        // alias, because it owns the spawn-and-configure lifecycle. The
        // refusal names it so the fix is the next thing the reader sees.
        refuse_alias_on_raw_channel(provider)?;
        magma_plugin::import_resource_state(self.channel.clone(), type_name, id)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The [`PluginImportEnvironment`] alias guard, as a free function so it
/// is reachable from a test — an `H2Channel` only exists as the result of
/// a real dial, so the guard could not otherwise be exercised without
/// spawning a provider, and an unexercised guard is not a gate.
fn refuse_alias_on_raw_channel(provider: &ProviderInstance) -> Result<(), String> {
    match provider.alias() {
        None => Ok(()),
        Some(alias) => Err(TypedRefusal::AliasOnRawChannel {
            provider: provider.name().to_string(),
            alias: alias.to_string(),
        }
        .to_string()),
    }
}

/// Refusals this module renders into the `String` reason the
/// [`ImportEnvironment`] contract carries.
///
/// A typed error rendered through `Display` rather than a `format!()` at
/// the call site — the trait's error channel is a `String`, so the type
/// is what keeps the message single-sourced and the ★★ TYPED EMISSION
/// rule satisfied.
#[derive(Debug, thiserror::Error)]
enum TypedRefusal {
    #[error(
        "import of a resource pinned to provider instance `{provider}.{alias}` cannot be \
         served by PluginImportEnvironment: it drives one pre-dialed channel and cannot \
         select an instance, so issuing this import would ask whichever provider that \
         channel happens to be — a different account or region than declared. Use \
         ConfiguredImportEnvironment, which spawns and configures the named instance."
    )]
    AliasOnRawChannel { provider: String, alias: String },
}

// ── Real environment (correct): provider gRPC over a CONFIGURED conn ──

/// The production `ImportEnvironment` for `spec.importHints` pre-plan
/// adoption — drives the real provider `ImportResourceState` RPC over a
/// **fully spawned + configured** connection, the same
/// spawn→handshake→dial→get_schema→configure lifecycle
/// [`crate::engine::dial_configured_provider`] gives the apply engine's
/// own `Registry` (and which the engine's mid-apply
/// import-on-conflict adopt already rides — see
/// `engine::run_plan_with_providers`'s `Action::Create` arm).
///
/// [`PluginImportEnvironment`] above dials a RAW, UNCONFIGURED channel
/// and decodes the response's `DynamicValue.json` field. Both are real
/// gaps for a provider reached over a live provider binary:
///
/// 1. The Terraform plugin protocol requires `ConfigureProvider` /
///    `Configure` to run before any other provider RPC — providers
///    cache their API client / credentials during `Configure` and are
///    not contracted to behave correctly (some crash — see
///    `magma_plugin::provider`'s doc on the absent-`ClientCapabilities`
///    SIGSEGV) when called unconfigured.
/// 2. Every OTHER RPC in this codebase (`PlanResourceChange`,
///    `ApplyResourceChange`, `ReadResource`, `ReadDataSource`, and this
///    same `ImportResourceState` RPC called from the apply engine's
///    on-conflict path) round-trips its state via `DynamicValue.msgpack`
///    — the wire field `magma_cty` is byte-compatible with go-cty's own
///    msgpack codec for. `.json` is populated by real providers only as
///    an optional debug aid, never as the carrier of a resource's actual
///    attributes; a decoder that reads ONLY `.json` and treats `.msgpack`
///    as a hard error is decoding the wrong field for the response every
///    real provider actually sends.
///
/// `ConfiguredImportEnvironment` closes both gaps by reusing
/// [`crate::engine::dial_configured_provider`] (spawn once per unique
/// provider referenced by the directives, cached for this environment's
/// lifetime) and `ProviderConn::import_resource_state` + the schema's
/// implied `CtyType` to decode the returned `DynamicValue.msgpack` —
/// exactly the same decode `engine::apply_one` already performs on
/// `ReadResource`'s confirming refresh.
pub struct ConfiguredImportEnvironment<'a> {
    ctx: &'a crate::engine::ApplyContext,
    /// Providers dialed so far, keyed by provider INSTANCE (the default
    /// `github`, `cloudflare`, …). Guarded by a `tokio::sync::Mutex` because
    /// `ImportEnvironment::import_resource_state` takes `&self` (the
    /// trait's shared-reference contract) while
    /// `ProviderConn::import_resource_state` needs `&mut`.
    live: tokio::sync::Mutex<HashMap<magma_types::ProviderInstance, crate::engine::LiveProvider>>,
}

impl<'a> ConfiguredImportEnvironment<'a> {
    /// Build an environment that will lazily dial + configure providers
    /// against `ctx` (workspace dir for provider binary resolution +
    /// per-provider `ConfigureProvider` config + terraform_version).
    #[must_use]
    pub fn new(ctx: &'a crate::engine::ApplyContext) -> Self {
        Self {
            ctx,
            live: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ImportEnvironment for ConfiguredImportEnvironment<'_> {
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
        provider: &ProviderInstance,
    ) -> Result<Vec<ImportedInstance>, String> {
        // The instance the CALLER resolved — an `ImportTarget::Pinned`
        // hint's declared instance, or the type-prefix default for a
        // bare one. It used to be inferred here from the type alone,
        // which always yielded the default instance and made an aliased
        // import unexpressible; the resolution moved to the caller
        // because the caller is the only place that knows.
        //
        // Two instances of one provider are two entries in `live`, so
        // they are two dialed + separately configured connections rather
        // than one cache hit serving the wrong account.
        let provider_instance = provider.clone();
        let mut live = self.live.lock().await;
        if !live.contains_key(&provider_instance) {
            let lp = crate::engine::dial_configured_provider(self.ctx, &provider_instance)
                .await
                .map_err(|e| e.to_string())?;
            live.insert(provider_instance.clone(), lp);
        }
        // Just inserted above (or already present) — infallible get.
        let lp = live
            .get_mut(&provider_instance)
            .expect("provider just dialed + inserted");

        // Drive the SHARED two-step adoption primitive — `ImportResourceState`
        // followed by the protocol-mandated confirming `ReadResource`, plus the
        // identity backfill — exactly as the apply engine's reactive
        // on-conflict arm does. This function used to call
        // `import_resource_state` alone and hand the raw STUB to `absorb()`,
        // which is how nine `github_repository` entries reached the
        // pleme-io-opensource state with `name: null, node_id: null`: present
        // at their address (so the plan stopped proposing a Create) but
        // identity-less forever (so every dependent's
        // `${github_repository.X.node_id}` resolved to null, and magma's
        // `refresh` being an M0.10 no-op meant it never self-healed). Two
        // adoption entry points, one protocol — implemented once.
        //
        // Unpaced (`None`): the prepass runs pre-plan against a handful of
        // operator-resolved targets, not the apply's full mutation stream.
        match crate::engine::import_and_confirm(lp, type_name, id, None)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(attrs) => Ok(vec![ImportedInstance {
                type_name: type_name.to_string(),
                attributes: attrs,
                // `ProviderConn::import_resource_state` (like the apply
                // engine's own on-conflict adopt call) returns only the
                // decoded state — the wire response's `private` bytes
                // aren't threaded through. Matches the existing,
                // already-proven mid-apply adopt path's behavior; not a
                // regression introduced here.
                private: Vec::new(),
            }]),
            // The provider imported nothing (cty-null state) — an empty
            // instance list; `absorb()` records a tracked-but-empty
            // placeholder, same as the raw path's empty-state case.
            None => Ok(Vec::new()),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Parse a canonical `type.name` address string into a root-module
/// `ResourceAddress`. The address syntax mirrors what
/// `assert_import_absorbs` keys on (`type_id.name`). Nested-module +
/// `for_each`/count-keyed addresses (`module.x.type.name["k"]`) are an
/// M0.x extension — the operator's importHints are flat root-module
/// addresses today.
fn parse_address(address: &str) -> Result<ResourceAddress, ImportPrepassError> {
    let (type_id, name) = address
        .split_once('.')
        .ok_or_else(|| ImportPrepassError::MalformedAddress(address.to_string()))?;
    if type_id.is_empty() || name.is_empty() {
        return Err(ImportPrepassError::MalformedAddress(address.to_string()));
    }
    Ok(ResourceAddress {
        module: ModulePath::root(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId(type_id.to_string()),
        name: name.to_string(),
        key: None,
    })
}

/// Is `address` already present in `state` (as a managed resource)?
fn state_contains(state: &State, address: &ResourceAddress) -> bool {
    state.resources.iter().any(|r| r.address == *address)
}

/// Absorb the imported instances into state under `target_address`.
/// The provider may return several instances (e.g. dependent
/// resources); the one whose `type_name` matches the target's type maps
/// to the target address; any extras are skipped in M0 (a follow-up
/// maps them by their reported type+id, per theory/MAGMA.md §ApplyRpcContract).
/// `provider` is the instance the import was issued to. It is recorded
/// on the state row, and it has to be: refresh selects a row's instance
/// from `StateResource.provider`, so a resource adopted out of a second
/// account and written down as alias-free has its next `ReadResource`
/// sent to the default account — where "it isn't there" is
/// indistinguishable from real deletion drift, and the row is dropped.
/// An import that reaches the right account and then forgets which one
/// it was is a delayed version of the same wrong-account failure.
fn absorb(
    state: &mut State,
    target_address: &ResourceAddress,
    instances: &[ImportedInstance],
    provider: &ProviderInstance,
) {
    // Prefer the instance whose reported type matches the target; fall
    // back to the first instance (single-resource imports — the common
    // case — always return exactly one).
    let chosen = instances
        .iter()
        .find(|i| i.type_name == target_address.type_id.0)
        .or_else(|| instances.first());

    let state_instances: Vec<StateInstance> = match chosen {
        Some(inst) => vec![inst.to_state_instance()],
        None => {
            // No instance returned — record an empty Ready instance so
            // the address is at least tracked (the next ReadResource
            // hydrates it). This keeps the import idempotent.
            vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::Value::Object(Default::default()),
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }]
        }
    };

    // Upsert: drop any prior instance at this address, then insert.
    state.resources.retain(|r| r.address != *target_address);
    let mut reference = provider_for(target_address);
    // Only the ALIAS is threaded. `source` stays the type-prefix
    // inference — the same limitation the apply path records, and the
    // same reason: nothing here reads `required_providers`, so a local
    // name that differs from the type prefix still resolves to the
    // prefix's source address.
    reference.alias = provider.alias().map(str::to_string);
    state.resources.push(StateResource {
        address: target_address.clone(),
        provider: reference,
        instances: state_instances,
    });
}

/// Infer the provider reference for an address from its type prefix.
/// Mirrors `magma_apply::default_provider_for`; kept local so the
/// prepass doesn't depend on a private fn. M0.x routes both through a
/// shared `magma-providers` registry lookup.
fn provider_for(address: &ResourceAddress) -> ProviderReference {
    let (namespace, name) = address
        .type_id
        .0
        .split_once('_')
        .map(|(prefix, _)| match prefix {
            "aws" => ("hashicorp", "aws"),
            "google" | "gcp" => ("hashicorp", "google"),
            "azurerm" => ("hashicorp", "azurerm"),
            "cloudflare" => ("cloudflare", "cloudflare"),
            "github" => ("integrations", "github"),
            "datadog" => ("datadog", "datadog"),
            "kubernetes" => ("hashicorp", "kubernetes"),
            "helm" => ("hashicorp", "helm"),
            "null" => ("hashicorp", "null"),
            "random" => ("hashicorp", "random"),
            "tls" => ("hashicorp", "tls"),
            "local" => ("hashicorp", "local"),
            "akeyless" => ("akeyless-community", "akeyless"),
            "hcloud" => ("hetznercloud", "hcloud"),
            "splunk" => ("splunk", "splunk"),
            _ => ("hashicorp", prefix),
        })
        .unwrap_or(("hashicorp", "null"));
    ProviderReference {
        source: format!("{namespace}/{name}"),
        name: name.into(),
        alias: None,
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn empty() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: Uuid::nil(),
            outputs: HashMap::new(),
            resources: Vec::new(),
        }
    }

    /// Mock environment: returns a canned state per (type, id), or an
    /// error for ids registered to fail. Records call count so the
    /// idempotency tests can assert "no RPC ran".
    #[derive(Default)]
    struct MockEnv {
        ok: HashMap<String, serde_json::Value>,
        fail: HashMap<String, String>,
        calls: Mutex<Vec<String>>,
    }

    impl MockEnv {
        fn with_ok(mut self, id: &str, ty: &str, attrs: serde_json::Value) -> Self {
            self.ok.insert(
                id.to_string(),
                serde_json::json!({"type": ty, "attrs": attrs}),
            );
            self
        }
        fn with_fail(mut self, id: &str, reason: &str) -> Self {
            self.fail.insert(id.to_string(), reason.to_string());
            self
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ImportEnvironment for MockEnv {
        async fn import_resource_state(
            &self,
            type_name: &str,
            id: &str,
            provider: &ProviderInstance,
        ) -> Result<Vec<ImportedInstance>, String> {
            // The INSTANCE is recorded alongside the call, because
            // "which instance was this import issued to" is the only
            // thing that distinguishes an import from the right account
            // from an import from the wrong one — and it is invisible in
            // the returned state either way.
            self.calls
                .lock()
                .unwrap()
                .push(format!("{type_name}/{id}@{provider}"));
            if let Some(reason) = self.fail.get(id) {
                return Err(reason.clone());
            }
            if let Some(canned) = self.ok.get(id) {
                return Ok(vec![ImportedInstance {
                    type_name: canned["type"].as_str().unwrap_or(type_name).to_string(),
                    attributes: canned["attrs"].clone(),
                    private: vec![],
                }]);
            }
            Err(format!("mock: no canned state for id {id}"))
        }
    }

    fn directives(pairs: &[(&str, &str)]) -> ImportDirectives {
        let mut d = ImportDirectives::default();
        for (a, i) in pairs {
            d = d.with_explicit(*a, *i);
        }
        d
    }

    #[tokio::test]
    async fn explicit_import_absorbs_into_state() {
        let env = MockEnv::default().with_ok(
            "cluster-role-id",
            "aws_iam_role",
            serde_json::json!({"name": "cluster-role", "id": "cluster-role-id"}),
        );
        let mut state = empty();
        let d = directives(&[("aws_iam_role.cluster", "cluster-role-id")]);

        let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        assert_eq!(outcome.newly_absorbed(), 1);
        assert!(outcome.all_succeeded());
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.type_id.0, "aws_iam_role");
        assert_eq!(state.resources[0].address.name, "cluster");
        assert_eq!(
            state.resources[0].instances[0].attributes["id"],
            "cluster-role-id"
        );
        assert_eq!(env.call_count(), 1);
    }

    // ── Aliased import ─────────────────────────────────────────────
    //
    // The last place a provider instance was inferred rather than
    // carried. `ImportDirectives` had no field for one, so an import was
    // always issued to the DEFAULT instance of the resource type's
    // provider — which means a resource living in a second account or
    // region could not be adopted at all. The RPC asked an account that
    // never held it and got "not found"; the silent variant is worse,
    // where something in the default account answers to the same id and
    // is adopted into an address that meant a different resource.

    /// The instance a hint names is the instance the RPC is issued to.
    #[tokio::test]
    async fn a_pinned_hint_issues_the_import_to_the_instance_it_names() {
        let env = MockEnv::default().with_ok(
            "i-west",
            "aws_instance",
            serde_json::json!({"id": "i-west"}),
        );
        let mut state = empty();
        let d = ImportDirectives::default().with_explicit_on(
            "aws_instance.west",
            "i-west",
            ProviderInstance::aliased("aws", "us_east_2").unwrap(),
        );

        let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        assert_eq!(outcome.newly_absorbed(), 1);
        assert_eq!(
            env.calls.lock().unwrap().as_slice(),
            ["aws_instance/i-west@aws.us_east_2"],
            "the import must be issued to the DECLARED instance, not the type-prefix default",
        );
    }

    /// …and the row it writes records that instance, or the next refresh
    /// reads the resource back through the default account and reports a
    /// live resource as deleted.
    #[tokio::test]
    async fn an_aliased_import_records_its_instance_on_the_state_row() {
        let env = MockEnv::default().with_ok(
            "i-west",
            "aws_instance",
            serde_json::json!({"id": "i-west"}),
        );
        let mut state = empty();
        let d = ImportDirectives::default().with_explicit_on(
            "aws_instance.west",
            "i-west",
            ProviderInstance::aliased("aws", "us_east_2").unwrap(),
        );

        run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        let row = &state.resources[0];
        assert_eq!(row.provider.alias.as_deref(), Some("us_east_2"));
        // `source` stays the type-prefix inference, unchanged.
        assert_eq!(row.provider.source, "hashicorp/aws");
    }

    /// A bare hint is every hint that exists today. It must keep meaning
    /// exactly what it meant: the default instance, and a row with no
    /// alias on it.
    #[tokio::test]
    async fn a_bare_hint_still_imports_through_the_default_instance() {
        let env = MockEnv::default().with_ok(
            "cluster-role-id",
            "aws_iam_role",
            serde_json::json!({"id": "cluster-role-id"}),
        );
        let mut state = empty();
        let d = directives(&[("aws_iam_role.cluster", "cluster-role-id")]);

        run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        assert_eq!(
            env.calls.lock().unwrap().as_slice(),
            ["aws_iam_role/cluster-role-id@aws"],
            "an un-pinned hint resolves to the type-prefix default instance",
        );
        assert_eq!(state.resources[0].provider.alias, None);
    }

    /// `PluginImportEnvironment` drives ONE pre-dialed channel and
    /// cannot select an instance, so it refuses an aliased import rather
    /// than issuing it down whichever channel it happens to hold —
    /// which would be an import from an unknown account, reported as
    /// success.
    #[test]
    fn a_raw_channel_environment_refuses_an_aliased_import() {
        let err =
            refuse_alias_on_raw_channel(&ProviderInstance::aliased("aws", "us_east_2").unwrap())
                .expect_err("an alias has no meaning on a single pre-dialed channel");
        assert!(
            err.contains("aws.us_east_2") && err.contains("ConfiguredImportEnvironment"),
            "the refusal must name the instance and the environment that CAN serve it: {err}",
        );
    }

    #[test]
    fn a_raw_channel_environment_still_serves_the_default_instance() {
        assert!(
            refuse_alias_on_raw_channel(&ProviderInstance::implied_by_type("aws_instance")).is_ok(),
            "the unaliased path — every import that exists today — must be untouched",
        );
    }

    #[tokio::test]
    async fn import_is_idempotent_when_already_in_state() {
        let env = MockEnv::default().with_ok(
            "role-id",
            "aws_iam_role",
            serde_json::json!({"id": "role-id"}),
        );
        let mut state = empty();
        let d = directives(&[("aws_iam_role.cluster", "role-id")]);

        // First run absorbs.
        let first = run_explicit_prepass(&env, &d, &mut state).await.unwrap();
        assert_eq!(first.newly_absorbed(), 1);
        assert_eq!(state.resources.len(), 1);

        // Second run is a NoOp — no RPC, no duplicate.
        let calls_before = env.call_count();
        let second = run_explicit_prepass(&env, &d, &mut state).await.unwrap();
        assert_eq!(second.newly_absorbed(), 0);
        assert_eq!(second.imported.len(), 1);
        assert!(!second.imported[0].absorbed);
        assert_eq!(state.resources.len(), 1, "no duplicate resource");
        assert_eq!(env.call_count(), calls_before, "no RPC on idempotent path");
    }

    #[tokio::test]
    async fn failed_import_is_isolated_not_a_panic() {
        let env = MockEnv::default()
            .with_ok(
                "good-id",
                "aws_iam_role",
                serde_json::json!({"id": "good-id"}),
            )
            .with_fail("bad-id", "provider: resource not found");
        let mut state = empty();
        let d = directives(&[
            ("aws_iam_role.good", "good-id"),
            ("aws_iam_role.bad", "bad-id"),
        ]);

        let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        // The good one absorbed; the bad one is a typed FailedImport,
        // not a panic, not an abort.
        assert_eq!(outcome.newly_absorbed(), 1);
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].address, "aws_iam_role.bad");
        assert!(outcome.failed[0].reason.contains("not found"));
        assert!(!outcome.all_succeeded());
        // Only the good resource landed in state.
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.name, "good");
    }

    #[tokio::test]
    async fn empty_directives_is_a_noop() {
        let env = MockEnv::default();
        let mut state = empty();
        let outcome = run_explicit_prepass(&env, &ImportDirectives::default(), &mut state)
            .await
            .unwrap();
        assert!(outcome.imported.is_empty());
        assert!(outcome.failed.is_empty());
        assert_eq!(env.call_count(), 0);
    }

    #[tokio::test]
    async fn malformed_address_is_a_typed_error() {
        let env = MockEnv::default().with_ok("x", "aws_iam_role", serde_json::json!({}));
        let mut state = empty();
        let d = directives(&[("no_dot_here", "x")]);
        let err = run_explicit_prepass(&env, &d, &mut state)
            .await
            .unwrap_err();
        assert!(matches!(err, ImportPrepassError::MalformedAddress(_)));
    }

    #[tokio::test]
    async fn import_on_conflict_absorbs_with_natural_id() {
        let env = MockEnv::default().with_ok(
            "my-repo",
            "github_repository",
            serde_json::json!({"name": "my-repo", "id": "my-repo"}),
        );
        let mut state = empty();
        let addr = parse_address("github_repository.galho").unwrap();

        let default_instance = ProviderInstance::implied_by_type(&addr.type_id.0);
        let absorbed = import_on_conflict(&env, &addr, "my-repo", &mut state, &default_instance)
            .await
            .unwrap();
        assert!(absorbed);
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.type_id.0, "github_repository");
        assert_eq!(
            state.resources[0].instances[0].attributes["name"],
            "my-repo"
        );
    }

    #[tokio::test]
    async fn import_on_conflict_idempotent_when_present() {
        let env = MockEnv::default().with_ok("my-repo", "github_repository", serde_json::json!({}));
        let mut state = empty();
        let addr = parse_address("github_repository.galho").unwrap();
        // Pre-populate.
        absorb(
            &mut state,
            &addr,
            &[ImportedInstance {
                type_name: "github_repository".into(),
                attributes: serde_json::json!({"name": "my-repo"}),
                private: vec![],
            }],
            &ProviderInstance::implied_by_type("github_repository"),
        );
        let calls_before = env.call_count();
        let default_instance = ProviderInstance::implied_by_type(&addr.type_id.0);
        let absorbed = import_on_conflict(&env, &addr, "my-repo", &mut state, &default_instance)
            .await
            .unwrap();
        assert!(!absorbed, "already-present is a NoOp");
        assert_eq!(env.call_count(), calls_before, "no RPC on idempotent path");
    }

    #[tokio::test]
    async fn deterministic_address_order() {
        // Receipt order is sorted by address regardless of map order.
        let env = MockEnv::default()
            .with_ok("a", "aws_iam_role", serde_json::json!({}))
            .with_ok("b", "aws_iam_role", serde_json::json!({}))
            .with_ok("c", "aws_iam_role", serde_json::json!({}));
        let mut state = empty();
        let d = directives(&[
            ("aws_iam_role.zeta", "c"),
            ("aws_iam_role.alpha", "a"),
            ("aws_iam_role.mid", "b"),
        ]);
        let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();
        let order: Vec<&str> = outcome
            .imported
            .iter()
            .map(|i| i.address.as_str())
            .collect();
        assert_eq!(
            order,
            vec![
                "aws_iam_role.alpha",
                "aws_iam_role.mid",
                "aws_iam_role.zeta"
            ]
        );
    }
}
