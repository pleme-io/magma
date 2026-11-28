//! magma-apply::import_prepass — adopt pre-existing resources into the
//! working state BEFORE the create-plan runs.
//!
//! This is the apply-side keystone that closes the
//! "create-plan 422s already-exists" failure class. Three directive
//! sources feed it:
//!
//!   * `explicit` — `spec.importHints`: address → provider-specific id.
//!   * `auto_on_conflict` — `importPolicy.autoOnConflict`: when a
//!     create is rejected as already-exists, retry it as an import
//!     using the resource's natural id.
//!   * the pre-create IDENTITY PROBE ([`run_identity_probe_prepass`]) —
//!     not operator-supplied at all: for a planned Create at an address
//!     absent from state whose type carries a probe rule, ask the live
//!     provider whether the resource's declared identity (its literal
//!     tag map) already exists, and absorb / proceed / refuse on the
//!     answer. Closes the twin-minting class the first two cannot see
//!     (types whose Create never conflicts — receipted 2026-11-15).
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
    Action, ImportDirectives, ImportTarget, ImportedInstance, ModulePath, ProviderInstance,
    ProviderReference, ResourceAddress, ResourceChange, ResourceKind, ResourceTypeId, State,
    StateInstance, StateResource,
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
    #[serde(default)]
    pub absent: Vec<AbsentImport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsentImport {
    pub address: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportVerdict {
    Imported { absorbed: bool },
    Absent,
    Failed { reason: String },
}

impl ImportPrepassOutcome {
    /// True iff every attempted import succeeded (or there was nothing
    /// to import). A non-empty `failed` list does NOT block apply — the
    /// failed addresses simply re-plan as Create.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty() && self.absent.is_empty()
    }

    #[must_use]
    pub fn verdict_for(&self, address: &str) -> Option<ImportVerdict> {
        if let Some(i) = self.imported.iter().find(|i| i.address == address) {
            return Some(ImportVerdict::Imported {
                absorbed: i.absorbed,
            });
        }
        if self.absent.iter().any(|a| a.address == address) {
            return Some(ImportVerdict::Absent);
        }
        self.failed
            .iter()
            .find(|f| f.address == address)
            .map(|f| ImportVerdict::Failed {
                reason: f.reason.clone(),
            })
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

    /// Read a provider DATA SOURCE with `config`, issued to `provider` —
    /// the read half of the pre-create identity probe
    /// ([`run_identity_probe_prepass`]).
    ///
    /// The three-way answer is load-bearing, because the probe's two
    /// failure directions demand opposite reactions:
    ///
    /// * `Ok(Some(result))` — the provider answered. The probe reads the
    ///   matched ids out of `result` and applies zero/one/many semantics.
    /// * `Ok(None)` — this environment CANNOT SERVE the read at all (the
    ///   provider is not dialable here, or the data source is absent from
    ///   its schema). The probe treats the address as unprobeable and
    ///   leaves it on exactly its pre-probe behavior — the same degrade
    ///   the plan-time refresh shows when no provider binary is cached.
    ///   Refusing creates here would block every workspace whose provider
    ///   cannot be reached, which is collateral scope, not safety.
    /// * `Err(reason)` — the read was ATTEMPTED and failed mid-flight.
    ///   Freshness was never proven, and an unproven fresh estate is not
    ///   a license to create: the probe refuses THAT ADDRESS (a typed
    ///   [`magma_types::ProbeRefusal`]), never the apply.
    async fn read_data_source(
        &self,
        data_source: &str,
        config: &serde_json::Value,
        provider: &ProviderInstance,
    ) -> Result<Option<serde_json::Value>, String>;
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
            Ok(instances) => match adoptable(&parsed, &instances) {
                Some(chosen) => {
                    absorb(state, &parsed, chosen, &instance);
                    debug!(%address, %id, count = instances.len(), "import prepass: absorbed");
                    outcome.imported.push(ImportedAddress {
                        address: address.clone(),
                        id: id.to_string(),
                        absorbed: true,
                    });
                }
                None => {
                    warn!(%address, %id, "import prepass: provider reported the resource absent; state left untouched");
                    outcome.absent.push(AbsentImport {
                        address: address.clone(),
                        id: id.to_string(),
                    });
                }
            },
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
    let chosen = adoptable(address, &instances).ok_or_else(|| {
        TypedRefusal::Absent {
            address: format!("{}.{}", address.type_id.0, address.name),
            id: natural_id.to_string(),
        }
        .to_string()
    })?;
    absorb(state, address, chosen, provider);
    Ok(true)
}

// ── The pre-create identity probe ──────────────────────────────────

/// The typed receipt of the identity probe — the third directive source,
/// after `explicit` hints and `auto_on_conflict`.
///
/// Per-address outcomes, mirroring [`ImportPrepassOutcome`]'s discipline:
/// an entry here is one address's verdict, never a verdict on the apply.
/// Siblings always proceed; a refusal blocks only ITS address's create
/// (via [`magma_types::Plan::probe_refusals`], which the apply engines
/// honour).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePrepassOutcome {
    /// Addresses absorbed into working state from a single live match —
    /// the plan that follows sees Update/NoOp, not Create.
    pub absorbed: Vec<ImportedAddress>,
    /// Addresses the probe confirmed FRESH (zero live matches) — the
    /// planned Create proceeds, now with evidence it mints no twin.
    pub fresh: Vec<String>,
    /// Addresses whose Create is refused. Every one names why, and the
    /// many-match refusals name every matched live id.
    pub refused: Vec<magma_types::ProbeRefusal>,
}

/// **magma never mints a twin.** For every managed resource this config
/// declares at an address ABSENT from state, whose type carries a probe
/// rule ([`crate::adopt::PROBE_RULES`]), ask the live provider whether
/// the resource's own declared identity (its literal tag map) already
/// exists:
///
/// * exactly one live match → absorb it into working state through the
///   SAME import machinery as every other adoption (after passing the
///   same identity gates), so the subsequent plan sees Update/NoOp;
/// * zero matches → fresh estate; the Create proceeds;
/// * multiple matches → a TYPED REFUSAL on that address alone, naming
///   every matched id — twins exist, a human decides;
/// * the probe could not complete → a typed refusal too: freshness was
///   never proven, and an unproven fresh estate is not a license to
///   create.
///
/// The law this closes (receipted 2026-11-15): a control-plane move left
/// magma applying leaves with EMPTY state against a LIVE estate, and
/// types whose Create can never return AlreadyExists (AWS mints unlimited
/// duplicates) silently re-created the whole estate as twins — the
/// reactive `auto_on_conflict` path never fired because there was no
/// conflict. The probe fires BEFORE the create, keyed on identity magma
/// can resolve without creating anything.
///
/// Skips (no probe rule; address already in state; declared tags missing,
/// empty, or not literal; provider/data source not servable) change
/// nothing: the address keeps exactly its pre-probe behavior. Idempotent:
/// an address already in state is not probed, no RPC.
///
/// Never returns `Err` — every failure is a per-address typed outcome in
/// the receipt. Called from [`crate::engine::refresh_then_plan`] whenever
/// provider access exists, for EVERY config; there is no opt-in, because
/// "do not mint twins" is not a policy.
pub async fn run_identity_probe_prepass<E: ImportEnvironment>(
    env: &E,
    cfg: &magma_config::Config,
    state: &mut State,
) -> ProbePrepassOutcome {
    let mut outcome = ProbePrepassOutcome::default();

    // Deterministic order (sorted by canonical address), so the receipt —
    // and any attestation over it — is stable across runs. The config's
    // own iteration is HashMap order.
    let mut addresses: Vec<ResourceAddress> = cfg
        .resource_addresses()
        .filter(|a| a.kind == ResourceKind::Managed)
        .collect();
    addresses.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

    for address in addresses {
        let type_name = address.type_id.0.as_str();
        let Some(rule) = crate::adopt::probe_rule_for(type_name) else {
            continue;
        };
        // Idempotency: already in state ⇒ nothing to probe, no RPC. The
        // plan will see Update/NoOp on its own.
        if state_contains(state, &address) {
            continue;
        }
        let Some(body) = cfg.resource_body(&address) else {
            continue;
        };
        // Split meta-arguments (provider, count, …) from provider
        // attributes. A body the splitter refuses (count, lifecycle) is a
        // body the planner will refuse too — not the probe's business.
        let Ok((meta, attrs)) = magma_config::split_resource_body(&address.to_string(), &body)
        else {
            continue;
        };
        let Some(tags) = crate::adopt::literal_tags(&attrs) else {
            debug!(
                %address,
                "identity probe: no literal tag identity declared; address keeps pre-probe behavior"
            );
            continue;
        };
        // The instance the DECLARATION names (an aliased provider), or the
        // type-prefix default — the same resolution a bare import hint
        // takes, so a resource in a second account is probed and adopted
        // through that account, not the default one.
        let instance = meta
            .provider
            .clone()
            .unwrap_or_else(|| ProviderInstance::implied_by_type(type_name));
        let filter = crate::adopt::probe_filter(tags);
        let label = address.to_string();

        match env
            .read_data_source(rule.list_data_source, &filter, &instance)
            .await
        {
            // Machinery unavailable — unprobeable, not refused.
            Ok(None) => {}
            Err(reason) => {
                warn!(%address, %reason, "identity probe: read failed; create refused (freshness unproven)");
                outcome.refused.push(unproven_refusal(&label, &reason));
            }
            Ok(Some(result)) => {
                let Some(ids) = crate::adopt::matched_ids(&result, rule.ids_attr) else {
                    let reason = format!(
                        "data source {} answered without a usable `{}` attribute",
                        rule.list_data_source, rule.ids_attr
                    );
                    warn!(%address, %reason, "identity probe: contract miss; create refused");
                    outcome.refused.push(unproven_refusal(&label, &reason));
                    continue;
                };
                match ids.as_slice() {
                    [] => {
                        debug!(%address, "identity probe: zero live matches; create proceeds (fresh estate)");
                        outcome.fresh.push(label);
                    }
                    [id] => {
                        match env.import_resource_state(type_name, id, &instance).await {
                            Err(reason) => {
                                warn!(%address, %id, %reason, "identity probe: matched live id but import failed; create refused");
                                outcome.refused.push(mismatch_refusal(&label, id, reason));
                            }
                            Ok(instances) => match adoptable(&address, &instances) {
                                None => {
                                    let reason = "import returned no adoptable state".to_string();
                                    warn!(%address, %id, "identity probe: {reason}; create refused");
                                    outcome.refused.push(mismatch_refusal(&label, id, reason));
                                }
                                Some(chosen) => {
                                    // THE IDENTITY GATES, same two the
                                    // reactive path runs: natural_id's
                                    // attribute gate (silence is not
                                    // disagreement) and the probe's own
                                    // tag gate (the tags ARE the probe's
                                    // key). A constructed change carries
                                    // the declared attrs into
                                    // `verify_identity` unmodified.
                                    let probe_change = ResourceChange {
                                        address: address.clone(),
                                        action: Action::Create,
                                        before: None,
                                        after: Some(attrs.clone()),
                                        reasons: Vec::new(),
                                        meta: Default::default(),
                                    };
                                    if let Err(m) = crate::natural_id::verify_identity(
                                        &probe_change,
                                        Some(&attrs),
                                        &chosen.attributes,
                                    ) {
                                        let reason = format!(
                                            "identity mismatch on `{}`: planned {:?}, imported {:?}",
                                            m.attr, m.planned, m.imported
                                        );
                                        warn!(%address, %id, "identity probe: {reason}; create refused");
                                        outcome.refused.push(mismatch_refusal(&label, id, reason));
                                        continue;
                                    }
                                    if let Err(m) =
                                        crate::adopt::verify_declared_tags(tags, &chosen.attributes)
                                    {
                                        let reason = format!(
                                            "declared tag `{}` disagrees: planned {:?}, imported {:?}",
                                            m.tag, m.planned, m.imported
                                        );
                                        warn!(%address, %id, "identity probe: {reason}; create refused");
                                        outcome.refused.push(mismatch_refusal(&label, id, reason));
                                        continue;
                                    }
                                    absorb(state, &address, chosen, &instance);
                                    debug!(%address, %id, "identity probe: absorbed the one live match; plan will see Update/NoOp");
                                    outcome.absorbed.push(ImportedAddress {
                                        address: label,
                                        id: id.clone(),
                                        absorbed: true,
                                    });
                                }
                            },
                        }
                    }
                    many => {
                        warn!(
                            %address,
                            ids = many.join(","),
                            "identity probe: multiple live matches; create refused — twins exist, a human decides"
                        );
                        outcome.refused.push(many_match_refusal(&label, many));
                    }
                }
            }
        }
    }

    outcome
}

/// A refusal whose cause is "the probe could not prove freshness".
/// `matched_ids` is empty on purpose: nothing was confidently matched,
/// and the distinction is the receipt's to carry.
fn unproven_refusal(address: &str, reason: &str) -> magma_types::ProbeRefusal {
    magma_types::ProbeRefusal {
        address: address.to_string(),
        matched_ids: Vec::new(),
        reason: format!(
            "identity probe for {address} could not prove a fresh estate ({reason}); \
             refusing to create a possible twin"
        ),
    }
}

/// A refusal for the one live id that matched but was not adoptable as
/// the planned resource (import failed, nothing adoptable, identity or
/// tag mismatch). Creating now would mint a twin of a KNOWN id.
fn mismatch_refusal(address: &str, id: &str, detail: String) -> magma_types::ProbeRefusal {
    magma_types::ProbeRefusal {
        address: address.to_string(),
        matched_ids: vec![id.to_string()],
        reason: format!(
            "identity probe for {address} matched live id {id} but could not adopt it \
             ({detail}); refusing to create a twin of a known resource"
        ),
    }
}

/// THE 2026-11-15 refusal: several live resources carry the declared
/// identity, and every one is named — a human decides which is intended.
fn many_match_refusal(address: &str, ids: &[String]) -> magma_types::ProbeRefusal {
    magma_types::ProbeRefusal {
        address: address.to_string(),
        matched_ids: ids.to_vec(),
        reason: format!(
            "identity probe for {address} matched {} live resources ({}); refusing to \
             create a twin — import the intended one (spec.importHints) or remove the others",
            ids.len(),
            ids.join(", ")
        ),
    }
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

    async fn read_data_source(
        &self,
        _data_source: &str,
        _config: &serde_json::Value,
        _provider: &ProviderInstance,
    ) -> Result<Option<serde_json::Value>, String> {
        // Ok(None), not Err: this environment has one pre-dialed channel
        // and no schema, so it cannot serve a data-source read AT ALL —
        // machinery unavailable, the probe's skip arm, never a refusal.
        // `ConfiguredImportEnvironment` is the environment that can.
        Ok(None)
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
    #[error(
        "import of {address} ({id}): the provider reported the resource absent; nothing was adopted"
    )]
    Absent { address: String, id: String },
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
            None => Ok(Vec::new()),
        }
    }

    async fn read_data_source(
        &self,
        data_source: &str,
        config: &serde_json::Value,
        provider: &ProviderInstance,
    ) -> Result<Option<serde_json::Value>, String> {
        let provider_instance = provider.clone();
        let mut live = self.live.lock().await;
        if !live.contains_key(&provider_instance) {
            match crate::engine::dial_configured_provider(self.ctx, &provider_instance).await {
                Ok(lp) => {
                    live.insert(provider_instance.clone(), lp);
                }
                // Ok(None) — the probe's "machinery unavailable" arm. A
                // provider that cannot be dialed here also cannot serve
                // the refresh; the plan degrades the same way it always
                // has, and the address keeps its pre-probe behavior.
                Err(e) => {
                    tracing::warn!(
                        data_source,
                        provider = %provider_instance,
                        error = %e,
                        "identity probe: provider not dialable; address stays unprobed"
                    );
                    return Ok(None);
                }
            }
        }
        let lp = live
            .get_mut(&provider_instance)
            .expect("provider present or inserted above");
        crate::engine::read_data_source_decoded(lp, data_source, config)
            .await
            .map_err(|e| e.to_string())
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

fn adoptable<'i>(
    target_address: &ResourceAddress,
    instances: &'i [ImportedInstance],
) -> Option<&'i ImportedInstance> {
    let carries_attributes = |i: &&ImportedInstance| {
        i.attributes
            .as_object()
            .is_some_and(|o| o.values().any(|v| !v.is_null()))
    };
    instances
        .iter()
        .filter(carries_attributes)
        .find(|i| i.type_name == target_address.type_id.0)
        .or_else(|| instances.iter().find(carries_attributes))
}

/// Absorb the imported instances into state under `target_address`.
/// The provider may return several instances (e.g. dependent
/// resources); the one whose `type_name` matches the target's type maps
/// to the target address; any extras are skipped in M0 (a follow-up
/// maps them by their reported type+id).
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
    chosen: &ImportedInstance,
    provider: &ProviderInstance,
) {
    let state_instances: Vec<StateInstance> = vec![chosen.to_state_instance()];

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
        absent: HashMap<String, Vec<ImportedInstance>>,
        ds: HashMap<String, DsAnswer>,
        calls: Mutex<Vec<String>>,
    }

    /// The three answers a probe read can give, so the mock can exercise
    /// every arm of the `read_data_source` contract.
    enum DsAnswer {
        Answer(serde_json::Value),
        Unavailable,
        Fail(String),
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
        fn with_absent(mut self, id: &str, answer: Vec<ImportedInstance>) -> Self {
            self.absent.insert(id.to_string(), answer);
            self
        }
        fn with_ds(mut self, data_source: &str, result: serde_json::Value) -> Self {
            self.ds
                .insert(data_source.to_string(), DsAnswer::Answer(result));
            self
        }
        fn with_ds_unavailable(mut self, data_source: &str) -> Self {
            self.ds
                .insert(data_source.to_string(), DsAnswer::Unavailable);
            self
        }
        fn with_ds_fail(mut self, data_source: &str, reason: &str) -> Self {
            self.ds
                .insert(data_source.to_string(), DsAnswer::Fail(reason.to_string()));
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
            if let Some(answer) = self.absent.get(id) {
                return Ok(answer.clone());
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

        async fn read_data_source(
            &self,
            data_source: &str,
            _config: &serde_json::Value,
            provider: &ProviderInstance,
        ) -> Result<Option<serde_json::Value>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("ds:{data_source}@{provider}"));
            match self.ds.get(data_source) {
                None => Err(format!(
                    "mock: no canned answer for data source {data_source}"
                )),
                Some(DsAnswer::Answer(v)) => Ok(Some(v.clone())),
                Some(DsAnswer::Unavailable) => Ok(None),
                Some(DsAnswer::Fail(reason)) => Err(reason.clone()),
            }
        }
    }

    fn directives(pairs: &[(&str, &str)]) -> ImportDirectives {
        let mut d = ImportDirectives::default();
        for (a, i) in pairs {
            d = d.with_explicit(*a, *i);
        }
        d
    }

    fn absent_answers() -> Vec<(&'static str, Vec<ImportedInstance>)> {
        vec![
            ("no instance", Vec::new()),
            (
                "empty attribute map",
                vec![ImportedInstance {
                    type_name: "github_repository".into(),
                    attributes: serde_json::json!({}),
                    private: vec![],
                }],
            ),
            (
                "all-null attributes",
                vec![ImportedInstance {
                    type_name: "github_repository".into(),
                    attributes: serde_json::json!({"name": null, "node_id": null}),
                    private: vec![],
                }],
            ),
        ]
    }

    #[tokio::test]
    async fn an_absent_read_is_a_typed_absent_verdict_and_writes_nothing() {
        for (label, answer) in absent_answers() {
            let env = MockEnv::default().with_absent("onepassword-admin", answer);
            let mut state = empty();
            let d = directives(&[("github_repository.onepassword_admin", "onepassword-admin")]);

            let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

            assert_eq!(
                outcome.verdict_for("github_repository.onepassword_admin"),
                Some(ImportVerdict::Absent),
                "{label}"
            );
            assert!(outcome.imported.is_empty(), "{label}: {outcome:?}");
            assert!(outcome.failed.is_empty(), "{label}: {outcome:?}");
            assert!(!outcome.all_succeeded(), "{label}");
            assert!(state.resources.is_empty(), "{label}: {:?}", state.resources);
        }
    }

    #[tokio::test]
    async fn an_absent_import_is_retried_as_absent_not_absorbed_as_present() {
        let env = MockEnv::default().with_absent("onepassword-admin", Vec::new());
        let mut state = empty();
        let d = directives(&[("github_repository.onepassword_admin", "onepassword-admin")]);

        run_explicit_prepass(&env, &d, &mut state).await.unwrap();
        let second = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        assert_eq!(
            second.verdict_for("github_repository.onepassword_admin"),
            Some(ImportVerdict::Absent)
        );
        assert!(state.resources.is_empty());
    }

    #[tokio::test]
    async fn an_on_conflict_import_of_an_absent_object_refuses_and_writes_nothing() {
        for (label, answer) in absent_answers() {
            let env = MockEnv::default().with_absent("onepassword-admin", answer);
            let mut state = empty();
            let addr = parse_address("github_repository.onepassword_admin").unwrap();

            let r = import_on_conflict(
                &env,
                &addr,
                "onepassword-admin",
                &mut state,
                &ProviderInstance::implied_by_type("github_repository"),
            )
            .await;

            assert!(r.unwrap_err().contains("absent"), "{label}");
            assert!(state.resources.is_empty(), "{label}");
        }
    }

    #[tokio::test]
    async fn verdicts_cover_imported_absent_and_failed() {
        let env = MockEnv::default()
            .with_ok(
                "live",
                "github_repository",
                serde_json::json!({"name": "live"}),
            )
            .with_absent("gone", Vec::new())
            .with_fail("broken", "403 forbidden");
        let mut state = empty();
        let d = directives(&[
            ("github_repository.live", "live"),
            ("github_repository.gone", "gone"),
            ("github_repository.broken", "broken"),
        ]);

        let outcome = run_explicit_prepass(&env, &d, &mut state).await.unwrap();

        assert_eq!(
            outcome.verdict_for("github_repository.live"),
            Some(ImportVerdict::Imported { absorbed: true })
        );
        assert_eq!(
            outcome.verdict_for("github_repository.gone"),
            Some(ImportVerdict::Absent)
        );
        assert_eq!(
            outcome.verdict_for("github_repository.broken"),
            Some(ImportVerdict::Failed {
                reason: "403 forbidden".into()
            })
        );
        assert_eq!(outcome.verdict_for("github_repository.never"), None);
        assert_eq!(state.resources.len(), 1);
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
            &ImportedInstance {
                type_name: "github_repository".into(),
                attributes: serde_json::json!({"name": "my-repo"}),
                private: vec![],
            },
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
            .with_ok("a", "aws_iam_role", serde_json::json!({"id": "a"}))
            .with_ok("b", "aws_iam_role", serde_json::json!({"id": "b"}))
            .with_ok("c", "aws_iam_role", serde_json::json!({"id": "c"}));
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

    // ── The pre-create identity probe ───────────────────────────────
    //
    // The 2026-11-15 defect class, receipted: a control-plane move left
    // magma applying leaves with EMPTY state against a LIVE estate.
    // Types whose Create can never return AlreadyExists (AWS mints
    // unlimited duplicates) silently re-created the estate as full twins
    // with identical tags. These tests are the law's lock.

    fn house_tags() -> serde_json::Value {
        serde_json::json!({
            "Name": "engenho",
            "pleme.io/managed": "true"
        })
    }

    fn vpc_config(tags: serde_json::Value) -> magma_config::Config {
        magma_config::Config::from_json(serde_json::json!({
            "resource": {
                "aws_vpc": {
                    "main": {
                        "cidr_block": "10.0.0.0/16",
                        "tags": tags
                    }
                }
            }
        }))
        .expect("valid config")
    }

    /// THE regression lock, both halves of the 11-15 shape: state absent,
    /// live estate holds one tag-matching resource, and the plan proposes
    /// a Create (the twin the pre-feature path minted, paid for 13 days).
    /// The probe must turn that Create into an absorb, so the SAME plan
    /// call afterwards sees Update/NoOp — never Create.
    #[tokio::test]
    async fn a_state_absent_create_against_a_live_estate_absorbs_instead_of_minting_a_twin() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-live"] }))
            .with_ok(
                "vpc-live",
                "aws_vpc",
                serde_json::json!({
                    "id": "vpc-live",
                    "tags": house_tags(),
                    "cidr_block": "10.0.0.0/16"
                }),
            );
        let mut state = empty();

        // BEFORE any probe: the plan proposes Create — this is the twin,
        // and it is what the pre-feature engine applied.
        let before = magma_plan::plan(&cfg, &state).unwrap();
        let create = before
            .resource_changes
            .iter()
            .find(|c| c.address.to_string() == "aws_vpc.main")
            .expect("the declared vpc is in the plan");
        assert_eq!(create.action, Action::Create);

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.absorbed.len(), 1, "{outcome:?}");
        assert_eq!(outcome.absorbed[0].address, "aws_vpc.main");
        assert_eq!(outcome.absorbed[0].id, "vpc-live");
        assert!(outcome.refused.is_empty(), "{outcome:?}");
        // The one live match is in WORKING STATE under the declared
        // address — absorbed, not scheduled for creation.
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.to_string(), "aws_vpc.main");
        assert_eq!(state.resources[0].instances[0].attributes["id"], "vpc-live");

        // AFTER: the same plan call no longer proposes a Create. The
        // estate is managed, not duplicated.
        let after = magma_plan::plan(&cfg, &state).unwrap();
        let settled = after
            .resource_changes
            .iter()
            .find(|c| c.address.to_string() == "aws_vpc.main")
            .expect("the absorbed vpc is in the plan");
        assert_ne!(
            settled.action,
            Action::Create,
            "the probe absorbed the live estate; a Create here is the twin"
        );
    }

    /// Zero live matches is a genuinely fresh estate — the Create
    /// proceeds, now with evidence it mints no twin.
    #[tokio::test]
    async fn zero_live_matches_is_a_licensed_fresh_create() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default().with_ds("aws_vpcs", serde_json::json!({ "ids": [] }));
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert!(outcome.absorbed.is_empty(), "{outcome:?}");
        assert!(outcome.refused.is_empty(), "{outcome:?}");
        assert_eq!(outcome.fresh, vec!["aws_vpc.main".to_string()]);
        assert!(state.resources.is_empty(), "nothing to absorb");
        // And the plan still proposes the create.
        let plan = magma_plan::plan(&cfg, &state).unwrap();
        let create = plan
            .resource_changes
            .iter()
            .find(|c| c.address.to_string() == "aws_vpc.main")
            .unwrap();
        assert_eq!(create.action, Action::Create);
    }

    /// Several live matches: a typed refusal on THAT address alone,
    /// naming every matched id. Twins exist; a human decides.
    #[tokio::test]
    async fn many_live_matches_refuse_the_create_naming_every_id() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default().with_ds(
            "aws_vpcs",
            serde_json::json!({ "ids": ["vpc-one", "vpc-two", "vpc-three"] }),
        );
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1, "{outcome:?}");
        let refusal = &outcome.refused[0];
        assert_eq!(refusal.address, "aws_vpc.main");
        assert_eq!(
            refusal.matched_ids,
            vec![
                "vpc-one".to_string(),
                "vpc-two".to_string(),
                "vpc-three".to_string()
            ]
        );
        for id in ["vpc-one", "vpc-two", "vpc-three"] {
            assert!(
                refusal.reason.contains(id),
                "reason names {id}: {}",
                refusal.reason
            );
        }
        assert!(state.resources.is_empty(), "nothing absorbed on refusal");
        assert!(outcome.absorbed.is_empty() && outcome.fresh.is_empty());
    }

    /// A probe read that fails mid-flight refuses the create: freshness
    /// was never proven, and an unproven fresh estate is not a license to
    /// create. `matched_ids` stays empty — nothing was confidently matched.
    #[tokio::test]
    async fn a_failed_probe_read_refuses_the_create_with_an_empty_match_list() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default().with_ds_fail("aws_vpcs", "throttled: rate exceeded");
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1, "{outcome:?}");
        let refusal = &outcome.refused[0];
        assert_eq!(refusal.address, "aws_vpc.main");
        assert!(refusal.matched_ids.is_empty());
        assert!(
            refusal.reason.contains("throttled"),
            "the refusal names the read failure: {}",
            refusal.reason
        );
        assert!(state.resources.is_empty());
    }

    /// A read the environment cannot serve (provider not dialable, data
    /// source absent from the schema) is UNPROBEABLE, not refused: the
    /// address keeps exactly its pre-probe behavior. Refusing here would
    /// block every workspace whose provider cannot be reached — collateral
    /// scope, not safety.
    #[tokio::test]
    async fn an_unservable_read_leaves_the_address_on_its_pre_probe_behavior() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default().with_ds_unavailable("aws_vpcs");
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome, ProbePrepassOutcome::default());
        assert!(state.resources.is_empty());
    }

    /// Per-address isolation: one address's refusal never aborts — or even
    /// delays — its siblings. The refused vpc and the fresh subnet are
    /// both recorded, each as its own typed outcome.
    #[tokio::test]
    async fn a_refusal_is_per_address_and_never_touches_siblings() {
        let cfg = magma_config::Config::from_json(serde_json::json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16", "tags": house_tags() }
                },
                "aws_subnet": {
                    "az": {
                        "vpc_id": "${aws_vpc.main.id}",
                        "cidr_block": "10.0.1.0/24",
                        "tags": { "Name": "engenho-az" }
                    }
                }
            }
        }))
        .unwrap();
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-a", "vpc-b"] }))
            .with_ds("aws_subnets", serde_json::json!({ "ids": [] }));
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(outcome.refused[0].address, "aws_vpc.main");
        assert_eq!(outcome.fresh, vec!["aws_subnet.az".to_string()]);
    }

    /// The probe is idempotent: once absorbed, the address is IN state, so
    /// a second probe run issues no RPC at all.
    #[tokio::test]
    async fn probing_an_address_already_in_state_is_a_noop() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-live"] }))
            .with_ok(
                "vpc-live",
                "aws_vpc",
                serde_json::json!({
                    "id": "vpc-live", "tags": house_tags()
                }),
            );
        let mut state = empty();

        run_identity_probe_prepass(&env, &cfg, &mut state).await;
        let calls_after_first = env.call_count();
        assert!(calls_after_first >= 2, "one read + one import ran");

        let second = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(second, ProbePrepassOutcome::default());
        assert_eq!(
            env.call_count(),
            calls_after_first,
            "no RPC on idempotent path"
        );
        assert_eq!(state.resources.len(), 1, "no duplicate resource");
    }

    /// No literal tag identity (missing / empty / interpolated tags), no
    /// probe: querying with a non-literal would read silence as freshness.
    #[tokio::test]
    async fn an_address_without_a_literal_tag_identity_is_not_probed() {
        for (label, tags) in [
            ("interpolated", serde_json::json!({ "Name": "${var.name}" })),
            ("empty", serde_json::json!({})),
            ("absent", serde_json::Value::Null),
        ] {
            let body = match tags {
                serde_json::Value::Null => serde_json::json!({ "cidr_block": "10.0.0.0/16" }),
                t => serde_json::json!({ "cidr_block": "10.0.0.0/16", "tags": t }),
            };
            let cfg = magma_config::Config::from_json(serde_json::json!({
                "resource": { "aws_vpc": { "main": body } }
            }))
            .unwrap();
            let env = MockEnv::default().with_ds_fail(
                "aws_vpcs",
                "any read here proves the probe ran, which is the bug",
            );
            let mut state = empty();

            let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

            assert_eq!(outcome, ProbePrepassOutcome::default(), "{label}");
            assert_eq!(env.call_count(), 0, "{label}: the probe must not run");
        }
    }

    /// A type with no probe rule is never probed — no behavior change for
    /// the rest of the ecosystem.
    #[tokio::test]
    async fn a_type_without_a_probe_rule_is_never_probed() {
        let cfg = magma_config::Config::from_json(serde_json::json!({
            "resource": {
                "aws_s3_bucket": {
                    "artifacts": { "bucket": "pleme-io-artifacts", "tags": house_tags() }
                }
            }
        }))
        .unwrap();
        let env = MockEnv::default();
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome, ProbePrepassOutcome::default());
        assert_eq!(env.call_count(), 0);
    }

    /// Adoption passes the SAME identity gates as the reactive path: the
    /// one live match whose tags disagree with the declaration is a
    /// refusal, not an absorb.
    #[tokio::test]
    async fn a_single_live_match_with_disagreeing_tags_is_refused_not_absorbed() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-stranger"] }))
            .with_ok(
                "vpc-stranger",
                "aws_vpc",
                serde_json::json!({
                    "id": "vpc-stranger",
                    "tags": { "Name": "other-estate", "pleme.io/managed": "true" }
                }),
            );
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1, "{outcome:?}");
        let refusal = &outcome.refused[0];
        assert_eq!(refusal.matched_ids, vec!["vpc-stranger".to_string()]);
        assert!(
            refusal.reason.contains("Name"),
            "the refusal names the disagreeing tag: {}",
            refusal.reason
        );
        assert!(state.resources.is_empty(), "a stranger is never absorbed");
    }

    /// The id matched but the import itself failed: creating now would
    /// mint a twin of a KNOWN id, so the create is refused naming it.
    #[tokio::test]
    async fn a_matched_id_whose_import_fails_refuses_the_create() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-live"] }))
            .with_fail("vpc-live", "provider: import rejected");
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1, "{outcome:?}");
        assert_eq!(outcome.refused[0].matched_ids, vec!["vpc-live".to_string()]);
        assert!(state.resources.is_empty());
    }

    /// A read that answers without the rule's ids attribute is a contract
    /// miss, not zero matches.
    #[tokio::test]
    async fn an_answer_without_ids_is_a_refused_contract_miss() {
        let cfg = vpc_config(house_tags());
        let env = MockEnv::default().with_ds("aws_vpcs", serde_json::json!({ "id": "sa-east-1" }));
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.refused.len(), 1, "{outcome:?}");
        assert!(outcome.refused[0].matched_ids.is_empty());
        assert!(
            outcome.refused[0].reason.contains("aws_vpcs"),
            "the refusal names the data source: {}",
            outcome.refused[0].reason
        );
    }

    /// The declared provider instance is the one probed — a resource in a
    /// second account is adopted through that account, never the default.
    #[tokio::test]
    async fn an_aliased_declaration_probes_the_instance_it_names() {
        let cfg = magma_config::Config::from_json(serde_json::json!({
            "resource": {
                "aws_vpc": {
                    "west": {
                        "provider": "aws.us_east_2",
                        "cidr_block": "10.0.0.0/16",
                        "tags": house_tags()
                    }
                }
            }
        }))
        .unwrap();
        let env = MockEnv::default()
            .with_ds("aws_vpcs", serde_json::json!({ "ids": ["vpc-west"] }))
            .with_ok(
                "vpc-west",
                "aws_vpc",
                serde_json::json!({ "id": "vpc-west", "tags": house_tags() }),
            );
        let mut state = empty();

        let outcome = run_identity_probe_prepass(&env, &cfg, &mut state).await;

        assert_eq!(outcome.absorbed.len(), 1, "{outcome:?}");
        assert_eq!(
            env.calls.lock().unwrap().as_slice(),
            [
                "ds:aws_vpcs@aws.us_east_2",
                "aws_vpc/vpc-west@aws.us_east_2"
            ],
            "both RPCs must be issued to the DECLARED instance"
        );
        assert_eq!(
            state.resources[0].provider.alias.as_deref(),
            Some("us_east_2")
        );
    }
}
