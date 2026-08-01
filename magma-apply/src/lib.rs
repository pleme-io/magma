//! magma-apply — apply engine.
//!
//! Drives provider RPC for each `ResourceChange` in a plan, updating
//! state per the provider's response. Parallelism + retries + budgets
//! come from `shigoto::Scheduler` (per `theory/MAGMA.md` §II.9).
//!
//! Execution is **sequential** within and across dependency waves, but it is
//! **resumable** and **durable**:
//!
//! * [`engine::run_plan_with_providers_resumable`] does bounded work per cycle
//!   and records it in an [`ApplyCursor`], so a plan too large to finish in one
//!   window converges over N cycles instead of failing. That is what removes
//!   plan size as a precondition for convergence.
//! * Given a [`checkpoint::CheckpointSink`], it writes `(state, cursor)`
//!   durably after **every** applied node and every newly-cached deferred read,
//!   so a process killed mid-cycle loses at most one node's work rather than
//!   the cycle's. Resumption without that is only bounded-loss on paper: the
//!   cursor a cycle returns is worth nothing to a process that never returns.
//!
//! The cursor is keyed on a content-addressed [`ChangeFingerprint`], not on the
//! address alone, so a recorded entry can never cause a *different* change to
//! the same resource to be silently skipped.
//!
//! ## Why execution is still sequential — the measured answer, not an omission
//!
//! In-wave **concurrency** is deliberately NOT implemented, and the reason is
//! arithmetic rather than effort:
//!
//! * `apply_one` acquires one token from a **single shared** `LeakyBucket`
//!   before every non-NoOp change. The default is `burst = 1` at 3600 rph —
//!   strict 1 request/second, no bursting (bursts are what trip a provider's
//!   secondary rate limit).
//! * A shared bucket is shared by *workers* too. For `N` mutations the
//!   makespan is `max(N / rate, N × rpc_latency / W)`; with `rate = 1/s` and
//!   sub-second provider RPCs the first term dominates for every `W`. Little's
//!   Law puts the useful worker count at `W* ≈ rate × rpc_latency ≈ 1`.
//! * Concretely: the pleme-io-opensource plan that motivated resumable cycles
//!   carries ~1040 mutations. At strict 1 req/s that is ~1040 s of pure pacing
//!   against a 600 s window — a 1.7× overrun that **no number of workers
//!   changes**, because they all queue on the same bucket.
//!
//! So the sequential loop is already at the rate ceiling, and adding workers
//! to it would buy nothing while adding real risk on the one code path that
//! mutates live cloud resources. What removes plan size as a precondition is
//! chunked resumption above, which is shipped.
//!
//! What IS shipped for concurrency is everything that must be true *before*
//! it could be turned on safely, so the decision rests on data rather than
//! intuition:
//!
//! * `apply_one` no longer takes `&mut State`. It records its writes into a
//!   [`engine::NodeRecord`] the caller replays, and those writes are keyed on
//!   the node's own address — so two nodes in one wave are disjoint **by
//!   construction**, not by convention.
//! * The wave decomposition is an opaque `magma_graph::Waves`; the accidental
//!   `.flatten()` that discarded it no longer compiles.
//! * Each cycle's receipt reports `pacer_wait_ms_total` vs `node_rpc_ms_total`
//!   — the rate-bound-vs-latency-bound split. Concurrency is worth revisiting
//!   exactly when a real receipt shows the latter dominating.
//!
//! The genuinely load-bearing next step is **not** a worker pool: it is that
//! the bucket is shared across *all* providers, so a plan touching github and
//! cloudflare is paced as though they were one API. Per-provider pacing (plus
//! per-provider grouping within a wave, which needs no connection cloning
//! because each provider already owns a distinct `LiveProvider`) is what would
//! raise the aggregate rate — and only then does concurrency have anything to
//! convert into throughput.
//!
//! The typed shape matches §II.9 — every apply operation surfaces as
//! a typed `ApplyChange` Job.

pub mod adopt;
pub mod checkpoint;
pub mod cursor;
pub mod engine;
pub mod import_prepass;
pub mod natural_id;
pub mod shigoto_jobs;

pub use checkpoint::{CheckpointError, CheckpointSink, MemoryCheckpointSink, NullCheckpointSink};

pub use cursor::{
    ApplyCursor, ChangeFingerprint, CompletedChange, CursorError, CycleOutcome, CycleStats,
    DataResult, Progress, Quantum, Resume,
};

pub use import_prepass::{
    ConfiguredImportEnvironment, FailedImport, ImportEnvironment, ImportPrepassOutcome,
    ImportedAddress, PluginImportEnvironment, import_on_conflict, run_explicit_prepass,
};

use std::collections::HashMap;

use chrono::Utc;
use magma_types::{
    Action, InstanceStatus, Plan, ProviderReference, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State, StateInstance, StateResource,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("apply failed for {address:?}: {reason}")]
    Failed {
        address: ResourceAddress,
        reason: String,
    },
    #[error("missing provider for resource {0:?}")]
    MissingProvider(ResourceAddress),
    #[error("state update conflict: {0}")]
    StateConflict(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

// ── ApplyOutcome ───────────────────────────────────────────────────

/// The output of `run_plan` — typed receipt summarizing what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub plan_id: magma_types::PlanId,
    pub state: State,
    pub applied: Vec<AppliedChange>,
    pub failed: Vec<FailedChange>,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub reason: String,
}

// ── Apply engine (M0 — structural; provider RPC integration in M0.x) ──

/// Apply a `Plan` against `state`, mutating state in place per each
/// `ResourceChange`. M0 implementation is the structural diff:
/// Create produces a fresh `StateInstance` with the planned attributes;
/// Delete removes the resource from state; NoOp is a passthrough.
/// Update / Replace / Forget paths land alongside the provider-RPC
/// integration (M0.x) once `PlanResourceChange` + `ApplyResourceChange`
/// gRPC calls flow through the spawned `Plugin`.
///
/// This is the typed in-memory `apply` step in the §II.9 work-graph;
/// downstream consumers (chains, MCP `magma_apply`, CLI `magma apply`)
/// invoke this function directly with typed values.
pub fn run_plan(plan: &Plan, state: &mut State) -> Result<ApplyOutcome, ApplyError> {
    let started_at = Utc::now();
    let mut applied = Vec::new();
    let mut failed = Vec::new();

    // Resolution map (`{type → {name → attributes}}`), seeded from
    // state that already exists, then grown as each change in THIS
    // pass is structurally applied. This M0 structural apply talks to
    // no provider (see module docs), so unlike
    // `engine::run_plan_with_providers` (which resolves refs via
    // `substitute_refs` before the provider call) it must resolve
    // `${type.name.attr}` references itself before writing `after`
    // into state — otherwise a resource that references a sibling
    // (`vpc_id = "${aws_vpc.main.id}"`) would have that literal,
    // UNRESOLVED string persisted as if it were a concrete attribute
    // value. A later plan — which now correctly resolves references,
    // see BUG 1 in `magma-plan` — would then compare that stale
    // literal against a freshly-resolved value and report spurious
    // drift, breaking the apply-convergence law
    // (`magma-test-laws::assert_apply_converges`).
    let mut state_map = magma_config::state_resolution_map(state);

    // NoOp changes need no resolution or ordering — apply them first,
    // in plan order (unchanged behavior; mirrors
    // `engine::run_plan_with_providers`'s own noops-first split).
    let (noops, reals): (Vec<&ResourceChange>, Vec<&ResourceChange>) = plan
        .resource_changes
        .iter()
        .partition(|c| matches!(c.action, Action::NoOp));

    for change in noops {
        match apply_one(change, state, &mut state_map) {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(FailedChange {
                address: change.address.clone(),
                action: change.action,
                reason: e.to_string(),
            }),
        }
    }

    // Real changes are applied in DEPENDENCY order, not plan order —
    // plan order is alphabetical by (type_id, name) (see
    // `magma_plan::plan`'s deterministic sort), which is NOT
    // dependency order: e.g. `github_branch_protection_v3` sorts
    // before `github_repository` even when the former's config
    // references the latter. This module has no provider RPC to defer
    // resolution to, so getting apply ORDER right is what makes
    // reference RESOLUTION correct (`resolve_for_structural_apply`
    // below) — mirrors `engine::run_plan_with_providers`'s own
    // `ResourceGraph`-based ordering. Falls back to plan order on a
    // cycle / graph error — never refuses to apply.
    for change in dependency_ordered(&reals) {
        match apply_one(change, state, &mut state_map) {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(FailedChange {
                address: change.address.clone(),
                action: change.action,
                reason: e.to_string(),
            }),
        }
    }

    // Bump state serial when anything changed.
    if !applied.is_empty() {
        state.serial = state.serial.saturating_add(1);
    }

    Ok(ApplyOutcome {
        plan_id: plan.id,
        state: state.clone(),
        applied,
        failed,
        started_at,
        finished_at: Utc::now(),
    })
}

fn apply_one(
    change: &ResourceChange,
    state: &mut State,
    state_map: &mut HashMap<String, serde_json::Value>,
) -> Result<AppliedChange, ApplyError> {
    match change.action {
        Action::NoOp => Ok(AppliedChange {
            address: change.address.clone(),
            action: Action::NoOp,
            before: change.before.clone(),
            after: change.after.clone(),
        }),

        Action::Create | Action::Read => {
            let attributes = resolve_for_structural_apply(change.after.as_ref(), state_map);
            // 0: this M0 structural path never talks to a provider (see
            // module docs), so there is no real schema version to stamp —
            // see `insert_resource`'s doc for why 0 here is honest, not a
            // bug. The real value is stamped by `engine::apply_one`, which
            // DOES hold a live provider connection.
            insert_resource(state, &change.address, attributes.clone(), 0);
            magma_config::insert_into_resolution_map(state_map, &change.address, &attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: None,
                after: change.after.clone(),
            })
        }

        Action::Delete | Action::Forget => {
            remove_resource(state, &change.address);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: None,
            })
        }

        Action::Update => {
            // M0: Update is treated as upsert against state. Real
            // attribute-level update via provider RPC lands in M0.x.
            let attributes = resolve_for_structural_apply(change.after.as_ref(), state_map);
            remove_resource(state, &change.address);
            // 0 — see the Create arm above: no provider is consulted on
            // this structural-only path.
            insert_resource(state, &change.address, attributes.clone(), 0);
            magma_config::insert_into_resolution_map(state_map, &change.address, &attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: Action::Update,
                before: change.before.clone(),
                after: change.after.clone(),
            })
        }

        Action::Replace | Action::CreateThenDelete | Action::DeleteThenCreate => {
            // Delete-then-create variant: drop the prior instance, insert
            // the new one. Apply ORDER across resources is handled by
            // `dependency_ordered` in `run_plan`; this arm itself still
            // ignores intra-resource ordering nuance (single instance).
            remove_resource(state, &change.address);
            let attributes = resolve_for_structural_apply(change.after.as_ref(), state_map);
            // 0 — see the Create arm above: no provider is consulted on
            // this structural-only path.
            insert_resource(state, &change.address, attributes.clone(), 0);
            magma_config::insert_into_resolution_map(state_map, &change.address, &attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: change.after.clone(),
            })
        }
    }
}

/// Resolve `${type.name.attr}` references in a change's `after` config
/// against the running resolution map BEFORE it becomes a resource's new
/// state — the M0 structural counterpart of `engine::substitute_refs`'s
/// apply-time resolution (this module never dials a provider, so it must
/// do this resolution itself rather than let the provider's response
/// supply the concrete value). Falls back to the raw, unresolved value
/// on a resolution failure (e.g. a reference to a resource this same
/// pass hasn't reached yet) — never panics, never silently drops the
/// attribute set, exactly mirroring `magma-plan`'s own
/// safe-by-erring-toward-the-raw-value fallback.
fn resolve_for_structural_apply(
    after: Option<&serde_json::Value>,
    state_map: &HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(v) = after else {
        return serde_json::Value::Object(Default::default());
    };
    magma_config::resolve_config(v, state_map).unwrap_or_else(|_| v.clone())
}

/// Order `changes` so a resource that references a sibling
/// (`vpc_id = "${aws_vpc.main.id}"`) is always processed AFTER that
/// sibling. Mirrors `engine::run_plan_with_providers`'s own
/// dependency-graph ordering (`engine::collect_refs`/`engine::ref_target`
/// + `magma_graph::ResourceGraph`, reused rather than re-implemented) —
/// plan order (alphabetical by `(type_id, name)`, see `magma_plan::plan`)
/// is not dependency order. Falls back to the given order on a cycle /
/// graph error — never refuses to apply.
fn dependency_ordered<'a>(changes: &[&'a ResourceChange]) -> Vec<&'a ResourceChange> {
    let keys: std::collections::HashSet<(String, String)> = changes
        .iter()
        .map(|c| (c.address.type_id.0.clone(), c.address.name.clone()))
        .collect();
    let by_key: HashMap<(String, String), &'a ResourceChange> = changes
        .iter()
        .map(|c| ((c.address.type_id.0.clone(), c.address.name.clone()), *c))
        .collect();

    let mut graph = magma_graph::ResourceGraph::new();
    for c in changes {
        graph.add(c.address.clone());
    }
    for c in changes {
        let self_key = (c.address.type_id.0.clone(), c.address.name.clone());
        if let Some(after) = &c.after {
            for refstr in engine::collect_refs(after) {
                if let Some(dep_key) = engine::ref_target(&refstr) {
                    if dep_key != self_key && keys.contains(&dep_key) {
                        if let Some(dep) = by_key.get(&dep_key) {
                            graph.depend(c.address.clone(), dep.address.clone());
                        }
                    }
                }
            }
        }
    }

    match graph.waves() {
        // The ONE legitimate collapse of the wave decomposition in the
        // workspace. This is the structural, provider-free apply: it talks
        // to nothing, has no concurrency to gain, and genuinely wants a
        // single dependency-respecting order. Asking for that by name
        // (rather than `.flatten()`) is what keeps the *accidental* collapse
        // — the one that silently discarded the real engine's parallelism —
        // a compile error everywhere else.
        Ok(waves) => waves
            .into_sequential_order()
            .into_iter()
            .filter_map(|a| by_key.get(&(a.type_id.0.clone(), a.name.clone())).copied())
            .collect(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "magma-apply: dependency-graph error in structural apply — applying in plan order"
            );
            changes.to_vec()
        }
    }
}

/// Upsert `address`'s single instance into `state`. `schema_version`
/// SHOULD be the provider's CURRENT declared schema version for this
/// resource type (`magma_plugin::provider::ProviderSchema::resource_version_u64`)
/// — every production caller with a live provider connection
/// (`engine::apply_one`) passes it. Callers with no provider connection at
/// all (this module's structural-only `apply_one`/`run_plan`, which never
/// talks to a provider — see the module docs above) pass `0` explicitly:
/// that is an honest "no provider was consulted to confirm this," never a
/// silent guess. Stamping a wrong-but-nonzero version would be worse than
/// 0 — 0 is the one value [`crate::engine::refresh_state`]/
/// [`crate::engine::refresh_named`] can never mistake for "we already
/// checked and it matched," so a structurally-inserted instance always
/// gets a real UpgradeResourceState-mediated check on its first refresh.
pub(crate) fn insert_resource(
    state: &mut State,
    address: &ResourceAddress,
    attributes: serde_json::Value,
    schema_version: u64,
) {
    // Remove any existing then push the fresh instance.
    state.resources.retain(|r| r.address != *address);
    state.resources.push(StateResource {
        address: address.clone(),
        provider: default_provider_for(address),
        instances: vec![StateInstance {
            index_key: None,
            schema_version,
            attributes,
            sensitive_attribute_paths: Vec::new(),
            private: Vec::new(),
            dependencies: Vec::new(),
            status: InstanceStatus::Ready,
        }],
    });
}

pub(crate) fn remove_resource(state: &mut State, address: &ResourceAddress) {
    state.resources.retain(|r| r.address != *address);
}

pub(crate) fn default_provider_for(address: &ResourceAddress) -> ProviderReference {
    // Heuristic: resource type `aws_*` → hashicorp/aws, etc. M0.x replaces
    // this with a typed provider lookup from `magma-providers`.
    let type_name = &address.type_id.0;
    let (namespace, name) = type_name
        .split_once('_')
        .map(|(prefix, _)| match prefix {
            "aws" => ("hashicorp", "aws"),
            "google" | "gcp" => ("hashicorp", "google"),
            "azurerm" => ("hashicorp", "azurerm"),
            "cloudflare" => ("cloudflare", "cloudflare"),
            "datadog" => ("datadog", "datadog"),
            "kubernetes" => ("hashicorp", "kubernetes"),
            "helm" => ("hashicorp", "helm"),
            "null" => ("hashicorp", "null"),
            "random" => ("hashicorp", "random"),
            "tls" => ("hashicorp", "tls"),
            "local" => ("hashicorp", "local"),
            "external" => ("hashicorp", "external"),
            "archive" => ("hashicorp", "archive"),
            "akeyless" => ("akeyless-community", "akeyless"),
            "hcloud" => ("hetznercloud", "hcloud"),
            "splunk" => ("splunk", "splunk"),
            _ => ("hashicorp", prefix),
        })
        .unwrap_or(("hashicorp", "null"));
    let _ = type_name; // address is already destructured
    let _ = address.kind;
    ProviderReference {
        source: format!("{namespace}/{name}"),
        name: name.into(),
        alias: None,
    }
}

// silence unused warnings on ResourceKind / ResourceTypeId until M0.x
// wires the provider lookup through a real registry.
const _: fn(ResourceKind, ResourceTypeId) = |_, _| {};

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magma_types::{
        ChangeReason, ModulePath, PlanId, ResourceAddress, ResourceKind, ResourceTypeId,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn fresh_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: Uuid::new_v4(),
            outputs: HashMap::new(),
            resources: Vec::new(),
        }
    }

    fn addr(type_name: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_name.into()),
            name: name.into(),
            key: None,
        }
    }

    fn plan_with(changes: Vec<ResourceChange>) -> Plan {
        Plan {
            id: PlanId([0u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::new(),
            variables: HashMap::new(),
            resource_changes: changes,
            output_changes: Vec::new(),
            observation: magma_types::Observation::unrefreshed(),
        }
    }

    #[test]
    fn apply_create_adds_to_state() {
        let mut state = fresh_state();
        let p = plan_with(vec![ResourceChange {
            address: addr("aws_vpc", "main"),
            action: Action::Create,
            before: None,
            after: Some(json!({ "cidr_block": "10.0.0.0/16" })),
            reasons: vec![ChangeReason::NewResource],
        }]);

        let outcome = run_plan(&p, &mut state).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.failed.len(), 0);
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.type_id.0, "aws_vpc");
        assert_eq!(state.serial, 1);
    }

    #[test]
    fn apply_delete_removes_from_state() {
        let mut state = fresh_state();
        state.resources.push(StateResource {
            address: addr("aws_vpc", "main"),
            provider: default_provider_for(&addr("aws_vpc", "main")),
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: json!({ "id": "vpc-x" }),
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        });

        let p = plan_with(vec![ResourceChange {
            address: addr("aws_vpc", "main"),
            action: Action::Delete,
            before: Some(json!({ "id": "vpc-x" })),
            after: None,
            reasons: vec![ChangeReason::DeletedResource],
        }]);

        let outcome = run_plan(&p, &mut state).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(state.resources.len(), 0);
    }

    #[test]
    fn structural_apply_resolves_interpolated_references_before_persisting_state() {
        // Sibling of magma-plan's BUG 1, surfaced by that fix: this M0
        // structural apply never talks to a provider, so unlike
        // `engine::run_plan_with_providers` (which resolves references
        // via `substitute_refs` before the provider call) it must
        // resolve `${type.name.attr}` references itself before writing
        // a resource's new state. Otherwise the literal, unresolved
        // reference string is persisted as if it were a concrete
        // attribute value, and a later plan — which now correctly
        // resolves references — reports spurious drift against it,
        // breaking `magma-test-laws::assert_apply_converges`. Changes
        // are listed here with the REFERENCING resource first, to also
        // prove dependency ordering (not just plan order) resolves it.
        let mut state = fresh_state();
        let p = plan_with(vec![
            ResourceChange {
                address: addr("aws_subnet", "priv"),
                action: Action::Create,
                before: None,
                after: Some(json!({ "vpc_id": "${aws_vpc.main.id}" })),
                reasons: vec![ChangeReason::NewResource],
            },
            ResourceChange {
                address: addr("aws_vpc", "main"),
                action: Action::Create,
                before: None,
                after: Some(json!({ "id": "vpc-abc123" })),
                reasons: vec![ChangeReason::NewResource],
            },
        ]);

        let outcome = run_plan(&p, &mut state).unwrap();
        assert_eq!(
            outcome.failed.len(),
            0,
            "apply must not fail: {:?}",
            outcome.failed
        );
        let subnet = state
            .resources
            .iter()
            .find(|r| r.address.type_id.0 == "aws_subnet")
            .expect("subnet applied");
        assert_eq!(
            subnet.instances[0].attributes["vpc_id"],
            json!("vpc-abc123"),
            "state must hold the RESOLVED reference value, not the literal ${{...}} string"
        );
    }

    #[test]
    fn provider_inferred_for_known_prefixes() {
        let r = default_provider_for(&addr("aws_vpc", "x"));
        assert_eq!(r.source, "hashicorp/aws");
        let r = default_provider_for(&addr("cloudflare_record", "x"));
        assert_eq!(r.source, "cloudflare/cloudflare");
        let r = default_provider_for(&addr("akeyless_dfc_key", "x"));
        assert_eq!(r.source, "akeyless-community/akeyless");
    }
}
