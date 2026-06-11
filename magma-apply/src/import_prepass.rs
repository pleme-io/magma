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

use async_trait::async_trait;
use magma_types::{
    ImportDirectives, ImportedInstance, InstanceStatus, ModulePath, ProviderReference,
    ResourceAddress, ResourceKind, ResourceTypeId, State, StateInstance, StateResource,
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
    /// Call the provider's `ImportResourceState` for `(type_name, id)`.
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
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
    let mut entries: Vec<(&String, &String)> = directives.explicit.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    for (address, id) in entries {
        let parsed = parse_address(address)?;

        // Idempotency: already in state ⇒ NoOp, no RPC.
        if state_contains(state, &parsed) {
            debug!(%address, "import prepass: already in state, skipping (idempotent NoOp)");
            outcome.imported.push(ImportedAddress {
                address: address.clone(),
                id: id.clone(),
                absorbed: false,
            });
            continue;
        }

        match env.import_resource_state(&parsed.type_id.0, id).await {
            Ok(instances) => {
                absorb(state, &parsed, &instances);
                debug!(%address, %id, count = instances.len(), "import prepass: absorbed");
                outcome.imported.push(ImportedAddress {
                    address: address.clone(),
                    id: id.clone(),
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
                    id: id.clone(),
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
pub async fn import_on_conflict<E: ImportEnvironment>(
    env: &E,
    address: &ResourceAddress,
    natural_id: &str,
    state: &mut State,
) -> Result<bool, String> {
    if state_contains(state, address) {
        return Ok(false);
    }
    let instances = env
        .import_resource_state(&address.type_id.0, natural_id)
        .await?;
    absorb(state, address, &instances);
    Ok(true)
}

// ── Real environment: provider gRPC over a dialed channel ──────────

/// The production `ImportEnvironment` — drives the real provider
/// `ImportResourceState` RPC via `magma_plugin::import_resource_state`
/// over a dialed `tonic::transport::Channel`. The channel comes from a
/// spawned `magma_plugin::Plugin::dial()`. This is the one sanctioned
/// filesystem reach (loading + exec'ing the provider plugin binary)
/// per the ★★ MAGMA-NATIVE EXECUTION directive — everything else stays
/// in memory.
pub struct PluginImportEnvironment {
    channel: magma_plugin::Channel,
}

impl PluginImportEnvironment {
    /// Wrap a dialed provider channel. Cheap to clone — the channel is
    /// a multiplexed gRPC handle.
    #[must_use]
    pub fn new(channel: magma_plugin::Channel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl ImportEnvironment for PluginImportEnvironment {
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
    ) -> Result<Vec<ImportedInstance>, String> {
        magma_plugin::import_resource_state(self.channel.clone(), type_name, id)
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

/// Absorb the imported instances into state under `target_address`.
/// The provider may return several instances (e.g. dependent
/// resources); the one whose `type_name` matches the target's type maps
/// to the target address; any extras are skipped in M0 (a follow-up
/// maps them by their reported type+id, per theory/MAGMA.md §ApplyRpcContract).
fn absorb(state: &mut State, target_address: &ResourceAddress, instances: &[ImportedInstance]) {
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
                schema_version: 0,
                attributes: serde_json::Value::Object(Default::default()),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }]
        }
    };

    // Upsert: drop any prior instance at this address, then insert.
    state.resources.retain(|r| r.address != *target_address);
    state.resources.push(StateResource {
        address: target_address.clone(),
        provider: provider_for(target_address),
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
        ) -> Result<Vec<ImportedInstance>, String> {
            self.calls.lock().unwrap().push(format!("{type_name}/{id}"));
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
            d.explicit.insert((*a).to_string(), (*i).to_string());
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

        let absorbed = import_on_conflict(&env, &addr, "my-repo", &mut state)
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
        );
        let calls_before = env.call_count();
        let absorbed = import_on_conflict(&env, &addr, "my-repo", &mut state)
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
