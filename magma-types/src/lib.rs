//! magma-types — the typed primitive surface for the magma IaC executor.
//!
//! Every consumer crate codes against the types defined here. State, plans,
//! provider schemas, the resource graph, attestation receipts — all
//! ground in this crate. Per `theory/MAGMA.md` §III.
//!
//! Wire formats (Terraform JSON, terraform.tfstate v4, tfplugin5/6 protobuf)
//! are serializations of these typed values. Internal flow is typed
//! end-to-end; JSON appears only at the wire boundary.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod observation;

pub use observation::{Coverage, DriftVerdict, Observation, ObservationError, RefreshCounts};

// ── Identity ───────────────────────────────────────────────────────

/// Identifier for a workspace member crate that produces a typed resource.
/// Provider-scoped. Currently owns its string; M0 follow-up swaps to an
/// interned `&'static str` via `lasso` or similar once the lookup tables
/// are large enough to matter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceTypeId(pub String);

/// Module path within a configuration: `root` or `a.b.c`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ModulePath(pub Vec<String>);

impl ModulePath {
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

/// The kind of resource a `ResourceAddress` identifies.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::TypedDispatcher,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
    gen_platform::FromStrKind,
)]
#[serde(rename_all = "snake_case")]
#[discriminant(case = "snake", also_display)]
#[from_str_kind(case = "snake")]
pub enum ResourceKind {
    Managed,
    Data,
    Output,
    Local,
    Variable,
}

/// Instance key for `count` / `for_each`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InstanceKey {
    Index(u64),
    Key(String),
}

/// Canonical resource identity. Round-trips byte-equal through OpenTofu's
/// state-file format (`"aws_vpc.foo[\"bar\"]"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceAddress {
    pub module: ModulePath,
    pub kind: ResourceKind,
    pub type_id: ResourceTypeId,
    pub name: String,
    pub key: Option<InstanceKey>,
}

/// The ONE canonical rendering of an address — `module.…` prefix, the
/// `data.` marker, `type.name`, and the instance key.
///
/// This exists because there was no typed surface for it, so every consumer
/// hand-rolled `format!("{}.{}", type_id.0, name)` — which silently discards
/// `kind`, `module` and `key`. Six such call sites lived in pangea-operator
/// alone, and the one feeding `InfrastructureTemplate.status` rendered a data
/// source as `aws_security_group.shaar_concentrator`, indistinguishable in an
/// approval review from a managed resource of the same type and name. Losing
/// the `data.` prefix is not cosmetic there: it is what let a *read* read as a
/// *create* on the surface a human approves. (magma-state had the correct
/// renderer all along, private and unexported.)
///
/// Per ★★ TYPED EMISSION, a `Display`-family `write!()` is one of the three
/// sanctioned emission surfaces — so making this the type's `Display` both
/// gives every consumer the right answer for free and makes the hand-rolled
/// `format!` obviously wrong at a glance.
///
/// Round-trips with `magma_state`'s `parse_address_string` — that crate's
/// existing round-trip tests (base / counted / keyed / data / module-prefixed /
/// nested-module) are the proof, since `format_address_string` now delegates
/// here rather than keeping a second copy of the logic.
impl std::fmt::Display for ResourceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _; // for `write_char` below
        for part in &self.module.0 {
            write!(f, "module.{part}.")?;
        }
        if matches!(self.kind, ResourceKind::Data) {
            f.write_str("data.")?;
        }
        write!(f, "{}.{}", self.type_id.0, self.name)?;
        match &self.key {
            Some(InstanceKey::Index(i)) => write!(f, "[{i}]"),
            Some(InstanceKey::Key(k)) => {
                // Escape `"` and `\` so a key containing either cannot break
                // out of the bracket literal and change what a re-parse sees.
                f.write_str("[\"")?;
                for c in k.chars() {
                    match c {
                        '"' => f.write_str("\\\"")?,
                        '\\' => f.write_str("\\\\")?,
                        other => f.write_char(other)?,
                    }
                }
                f.write_str("\"]")
            }
            None => Ok(()),
        }
    }
}

/// Reference to a provider — namespace + name + alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderReference {
    pub source: String,        // e.g. "hashicorp/aws"
    pub name: String,          // e.g. "aws"
    pub alias: Option<String>, // e.g. "us-east-2"
}

// ── Schema (provider-reported) ─────────────────────────────────────

/// Provider schema; the typed shape every resource attribute conforms to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSchema {
    pub provider: Block,
    pub resource_schemas: HashMap<String, Block>,
    pub data_source_schemas: HashMap<String, Block>,
    pub functions: HashMap<String, FunctionSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub version: u64,
    pub attributes: HashMap<String, Attribute>,
    pub nested_blocks: HashMap<String, NestedBlock>,
    pub description: Option<String>,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub type_repr: String, // cty type-string serialization
    pub description: Option<String>,
    pub required: bool,
    pub optional: bool,
    pub computed: bool,
    pub sensitive: bool,
    pub write_only: bool,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedBlock {
    pub block: Block,
    pub nesting: NestingMode,
    pub min_items: u64,
    pub max_items: u64,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake")]
#[serde(rename_all = "snake_case")]
pub enum NestingMode {
    Single,
    List,
    Set,
    Map,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub parameters: Vec<FunctionParameter>,
    pub variadic: Option<FunctionParameter>,
    pub return_type: String,
    pub summary: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParameter {
    pub name: String,
    pub type_repr: String,
    pub description: Option<String>,
    pub nullable: bool,
}

// ── Plan ───────────────────────────────────────────────────────────

/// BLAKE3 hash of (config + prior state + variables + computed plan).
/// Two plans with the same `PlanId` are bit-equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub [u8; 32]);

/// The output of `magma plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: PlanId,
    pub created_at: DateTime<Utc>,
    pub config_root: PathBuf,
    pub variables: HashMap<String, serde_json::Value>,
    pub resource_changes: Vec<ResourceChange>,
    pub output_changes: Vec<OutputChange>,
    /// How much of `resource_changes[].before` is real, observed fact —
    /// the plan-time refresh's own trustworthiness, travelling with the
    /// data it qualifies.
    ///
    /// **Why the plan, and not only the bundle.** The refresh happens in
    /// the same call that produces this value
    /// (`magma_apply::engine::refresh_then_plan`), the `before` fields
    /// this qualifies live here, and this is the artifact that gets
    /// persisted and re-read across reconcile cycles and pod restarts. A
    /// trust record that lives only in a downstream receipt leaves the
    /// standalone plan artifact still able to lie.
    ///
    /// **Deliberately OUTSIDE [`PlanId`]** — the same exclusion, for the
    /// same reason, as [`Plan::created_at`]. `PlanId` addresses the
    /// *change set computed against the state we hold*: two observations
    /// of an unchanged world must hash equal, or nothing downstream can
    /// dedupe, cache, or resume by plan id. `kept_on_error` moves with
    /// transient RPC weather; folding it into the digest would mint a
    /// "new plan" on every flaky read and destroy exactly the property
    /// that makes `PlanId` worth having. The trust record is instead a
    /// first-class field a consumer must read — see
    /// [`Plan::drift_verdict`], which has no way to say "in sync" without
    /// an observation that supports the claim.
    ///
    /// The *bundle* id, by contrast, DOES cover the observation: a
    /// compliance receipt from which the "this was blind" record can be
    /// stripped without breaking verification is not a receipt.
    #[serde(default)]
    pub observation: Observation,
}

impl Plan {
    /// Stamp this plan with the trust record of the refresh that produced
    /// the state it was diffed against.
    ///
    /// The seam for any caller that runs its own refresh instead of going
    /// through `magma_apply::engine::refresh_then_plan`. Never widens a
    /// claim by accident: an observation is classified from counts, so
    /// stamping cannot manufacture coverage the refresh did not have.
    #[must_use]
    pub fn with_observation(mut self, observation: Observation) -> Self {
        self.observation = observation;
        self
    }

    /// Resources this plan intends to change (every non-`NoOp` change).
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.resource_changes
            .iter()
            .filter(|c| c.action != Action::NoOp)
            .count()
    }

    /// Resources whose desired state matched the state we hold (every
    /// `NoOp` change).
    ///
    /// This is the "observed and correct" half of reality-as-data, and it
    /// is only ever *evidence* when [`Plan::observation`] says the state it
    /// matched against was actually read back from the provider — which is
    /// precisely what [`Plan::drift_verdict`] enforces.
    #[must_use]
    pub fn in_sync_count(&self) -> usize {
        self.resource_changes
            .iter()
            .filter(|c| c.action == Action::NoOp)
            .count()
    }

    /// The honest answer to "does reality match desired state?".
    ///
    /// Total over every observation: an all-`NoOp` plan built on a blind
    /// refresh returns [`DriftVerdict::Unobserved`], never
    /// [`DriftVerdict::InSync`]. Gate "nothing to do" decisions on
    /// [`DriftVerdict::is_confirmed_in_sync`], never on an empty change
    /// list.
    #[must_use]
    pub fn drift_verdict(&self) -> DriftVerdict {
        self.observation
            .verdict(self.change_count(), self.in_sync_count())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub reasons: Vec<ChangeReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChange {
    pub name: String,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub sensitive: bool,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::TypedDispatcher,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
    gen_platform::FromStrKind,
)]
#[serde(rename_all = "snake_case")]
#[discriminant(case = "snake", also_display)]
#[from_str_kind(case = "snake")]
pub enum Action {
    NoOp,
    Create,
    Read,
    Update,
    Replace,
    Delete,
    Forget,
    CreateThenDelete,
    DeleteThenCreate,
}

// Fleet-wide dispatcher-catalog registrations for magma's IaC
// executor surface. Seventh consumer class adopting gen-platform's
// typed-dispatcher catamorphism. See
// theory/UNIFIED-COMPUTING-MODEL.md §VI.
gen_platform::register_dispatcher!("magma.resource-kind", ResourceKind);
gen_platform::register_dispatcher!("magma.action", Action);

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake")]
#[serde(rename_all = "snake_case")]
pub enum ChangeReason {
    NewResource,
    DeletedResource,
    AttributeDrift,
    RequiresReplace,
    ReplaceTriggeredBy(ResourceAddress),
    Tainted,
    ReplacedByCli,
}

// ── State ──────────────────────────────────────────────────────────

/// In-memory state; serializes to `terraform.tfstate` (schema v4) byte-equal
/// with OpenTofu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u64,
    pub terraform_version: String,
    pub serial: u64,
    pub lineage: Uuid,
    pub outputs: HashMap<String, OutputValue>,
    pub resources: Vec<StateResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateResource {
    pub address: ResourceAddress,
    pub provider: ProviderReference,
    pub instances: Vec<StateInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInstance {
    /// `count`/`for_each` instance key. `None` for a resource declared
    /// without either (the common case — the overwhelming majority of
    /// real-world state today, since neither `magma-config` nor Pangea
    /// currently expand `count`/`for_each` on the config side). Carried
    /// per-instance (not on the parent `StateResource.address`) to match
    /// real `terraform.tfstate` v4: one resource entry groups all of its
    /// instances, each tagged with its own `index_key`. See
    /// `magma_state::tfstate_v4` for the wire-format boundary.
    #[serde(default)]
    pub index_key: Option<InstanceKey>,
    pub schema_version: u64,
    pub attributes: serde_json::Value,
    /// Attribute-path markers for values the provider schema (or a
    /// config `sensitive = true`) flags as sensitive. Preserved
    /// opaquely — magma doesn't interpret the path grammar today, it
    /// only round-trips it so a real state file's sensitive-value
    /// redaction markers are never silently dropped.
    #[serde(default)]
    pub sensitive_attribute_paths: Vec<serde_json::Value>,
    pub private: Vec<u8>,
    pub dependencies: Vec<ResourceAddress>,
    pub status: InstanceStatus,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake")]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    Ready,
    Tainted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputValue {
    pub value: serde_json::Value,
    #[serde(default)]
    pub sensitive: bool,
    /// The output's type-constraint, as tofu encodes it (`"string"`, or
    /// a nested `["object", {...}]` form for complex types). `None`
    /// when this `OutputValue` was built in-process rather than read
    /// off a real state file; the tfstate v4 wire encoder infers a
    /// best-effort constraint from `value`'s JSON shape in that case.
    #[serde(default)]
    pub type_constraint: Option<serde_json::Value>,
}

// ── Import directives + results ────────────────────────────────────
//
// The typed channel through which an operator (pangea-operator) hands
// magma per-resource import IDs. Two shapes, both declarative and
// config-selected — never a hidden fallback:
//
//   1. `explicit` — an address → import-ID map. The operator's
//      `spec.importHints`. Each entry says "adopt the live resource
//      identified by this provider-specific id into this typed
//      address." Cloudflare DNS records use the `<zoneid>/<recordid>`
//      compound form; github_repository uses the repo name; an IAM
//      role uses the role name; etc.  magma passes the string verbatim
//      to `ImportResourceState`'s `id` field — the provider knows how
//      to parse its own id syntax.
//
//   2. `auto_on_conflict` — the operator's `importPolicy.autoOnConflict`.
//      When true, a create-plan that the provider rejects as
//      already-exists is retried as an import using the resource's
//      NATURAL id (the value the planner would otherwise create it
//      under — e.g. `github_repository`'s id is the repo name). This
//      is a config decision, made explicitly and logged, not a silent
//      retry.

/// Per-resource import directives carried from the operator into the
/// magma apply pipeline. This is the typed border between the
/// operator's `spec.importHints` / `importPolicy.autoOnConflict` and
/// magma's import prepass. Serializable so it threads through the
/// bundle / config / plan-input wire boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDirectives {
    /// Explicit `resource-address → import-ID` map. The address is the
    /// canonical Terraform address string (`cloudflare_zone.quero_cloud`,
    /// `cloudflare_dns_record.api`, `github_repository.galho`). The
    /// value is the provider-specific import id passed verbatim to
    /// `ImportResourceState`.
    #[serde(default)]
    pub explicit: HashMap<String, String>,
    /// When `true`, a create the provider rejects as already-exists is
    /// retried as an import using the resource's natural id. Mirrors the
    /// operator's `importPolicy.autoOnConflict`.
    #[serde(default)]
    pub auto_on_conflict: bool,
}

impl ImportDirectives {
    /// An empty directive set — no explicit hints, no auto-on-conflict.
    /// Equivalent to `Default::default()`; named for call-site clarity.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// True iff there's nothing to do: no explicit hints and
    /// auto-on-conflict disabled. The prepass short-circuits on this.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.explicit.is_empty() && !self.auto_on_conflict
    }

    /// Look up the explicit import id for a canonical address string.
    #[must_use]
    pub fn explicit_id(&self, address: &str) -> Option<&str> {
        self.explicit.get(address).map(String::as_str)
    }

    /// Insert an explicit `address → id` hint, builder-style.
    #[must_use]
    pub fn with_explicit(mut self, address: impl Into<String>, id: impl Into<String>) -> Self {
        self.explicit.insert(address.into(), id.into());
        self
    }

    /// Enable auto-on-conflict, builder-style.
    #[must_use]
    pub fn with_auto_on_conflict(mut self, on: bool) -> Self {
        self.auto_on_conflict = on;
        self
    }
}

/// One resource state returned by the provider's `ImportResourceState`
/// RPC, decoded from the wire `DynamicValue` into typed JSON
/// attributes. The typed image of tfplugin6's
/// `ImportResourceState.ImportedResource`.
///
/// A single import can return several `ImportedInstance`s (a provider
/// may surface dependent resources alongside the target). The prepass
/// absorbs each into state under the address its `type_name` + the
/// requested name map to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedInstance {
    /// The provider-reported resource type (e.g. `aws_iam_role`).
    pub type_name: String,
    /// The decoded resource attributes (from the `DynamicValue` JSON).
    pub attributes: serde_json::Value,
    /// Opaque provider private state bytes carried verbatim into the
    /// `StateInstance`.
    pub private: Vec<u8>,
}

impl ImportedInstance {
    /// Build a typed `StateInstance` from this imported result. The
    /// imported resource is always `Ready` (it pre-exists in the
    /// world); `schema_version` defaults to 0 — the planner's next
    /// `ReadResource`/`PlanResourceChange` upgrades it if the provider
    /// reports a newer schema.
    #[must_use]
    pub fn to_state_instance(&self) -> StateInstance {
        StateInstance {
            index_key: None,
            schema_version: 0,
            attributes: self.attributes.clone(),
            sensitive_attribute_paths: Vec::new(),
            private: self.private.clone(),
            dependencies: Vec::new(),
            status: InstanceStatus::Ready,
        }
    }
}

// ── Diagnostics ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub summary: String,
    pub detail: Option<String>,
    pub address: Option<ResourceAddress>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake")]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MagmaTypesError {
    #[error("invalid resource address: {0}")]
    InvalidAddress(String),
    #[error("schema validation failed: {0}")]
    SchemaViolation(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_directives_builder_and_lookup() {
        let d = ImportDirectives::none()
            .with_explicit("cloudflare_zone.quero_cloud", "zoneid")
            .with_auto_on_conflict(true);
        assert!(!d.is_empty());
        assert!(d.auto_on_conflict);
        assert_eq!(d.explicit_id("cloudflare_zone.quero_cloud"), Some("zoneid"));
        assert_eq!(d.explicit_id("absent"), None);
    }

    #[test]
    fn empty_import_directives_is_empty() {
        assert!(ImportDirectives::default().is_empty());
        // auto_on_conflict alone makes it non-empty (there's work to do).
        assert!(
            !ImportDirectives::default()
                .with_auto_on_conflict(true)
                .is_empty()
        );
    }

    #[test]
    fn import_directives_round_trip_through_serde() {
        let d = ImportDirectives::none()
            .with_explicit("github_repository.galho", "galho")
            .with_auto_on_conflict(true);
        let json = serde_json::to_value(&d).unwrap();
        let back: ImportDirectives = serde_json::from_value(json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn imported_instance_to_state_instance_is_ready() {
        let imported = ImportedInstance {
            type_name: "aws_iam_role".into(),
            attributes: serde_json::json!({"id": "role-1"}),
            private: vec![1, 2, 3],
        };
        let inst = imported.to_state_instance();
        assert_eq!(inst.attributes["id"], "role-1");
        assert_eq!(inst.private, vec![1, 2, 3]);
        assert_eq!(inst.status, InstanceStatus::Ready);
        assert_eq!(inst.schema_version, 0);
    }
}
