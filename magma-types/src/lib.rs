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
/// source as `aws_security_group.vpn-hub_concentrator`, indistinguishable in an
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

    /// Resources this plan intends to CHANGE — excludes both `NoOp` and
    /// `Read`.
    ///
    /// A `Read` is a data-source lookup: it mutates nothing, and it recurs on
    /// every plan because a data source has no state row to settle into. It is
    /// observation, not intent.
    ///
    /// This only became reachable once `magma_plan::plan` started EMITTING
    /// `Read` (3de7bbb) — before that an unread data source came out as
    /// `Create`, so "non-NoOp" was an accurate proxy for "intends to change".
    /// Making data sources honest turned that proxy false, and this count feeds
    /// operator-facing summaries where an inflated number reads as pending
    /// mutation.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.resource_changes
            .iter()
            .filter(|c| !matches!(c.action, Action::NoOp | Action::Read))
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

// ── Resource meta-arguments ────────────────────────────────────────
//
// A Terraform resource block mixes two populations of keys that look
// identical in rendered JSON: PROVIDER ATTRIBUTES (`region`, `tags`, …),
// which belong to the provider's schema, and META-ARGUMENTS
// (`provider`, `depends_on`, `count`, …), which belong to the executor
// and never reach the provider. magma carried the block as one untyped
// `serde_json::Value` and therefore could not tell them apart. Two
// silently-wrong consequences followed, and neither produced an error
// anywhere:
//
//   1. A meta-argument was handed to the cty encoder as if it were an
//      attribute. `magma_cty::from_json` builds a `CtyType::Object` by
//      iterating the SCHEMA's attributes, so an unknown key is dropped
//      without complaint — `provider = "aws.us_east_2"` simply evaporated
//      and the resource was applied through the DEFAULT `aws` provider.
//      On a multi-account or multi-region estate that is real
//      infrastructure created in the wrong account, reported as success.
//   2. The same key still counted as a config-declared attribute for
//      drift purposes (`magma_plan::declared_attributes_drifted`), and
//      no provider ever returns it in state — so a resource carrying any
//      meta-argument re-planned as `Update` on every single cycle,
//      forever.
//
// [`ResourceMeta`] is the fix at that layer: meta-arguments are parsed
// OUT of the block into a typed value before anything downstream sees
// the attributes, so the two populations are structurally distinct
// rather than distinguished by convention.

/// The provider instance a resource is applied through.
///
/// **An alias cannot be represented.** This type holds a bare local
/// provider name and has no field an alias could live in, so no code
/// path below the config boundary can carry — or mis-handle — a
/// resource routed to an aliased provider instance. That much is
/// *truly unrepresentable*.
///
/// The boundary itself is weaker and must not be described as more: a
/// config that *declares* an alias is refused by
/// [`TryFrom<String>`](#impl-TryFrom<String>-for-ProviderInstance) with
/// a typed error, which is **only mitigation** — a `Result::Err`, not an
/// impossibility. Refusal is nonetheless the correct behaviour while
/// magma cannot instantiate aliased providers: the alternative that
/// shipped until now was applying to the wrong account in silence.
///
/// Supporting aliases for real is a genuinely larger change than this
/// type — `magma_config::Config::providers` is a `HashMap<String, _>`
/// and so cannot even hold two blocks for one provider;
/// `ApplyContext::provider_configs` and the apply `Registry` are both
/// keyed by bare provider name. When that lands, this struct gains an
/// `alias` field and every consumer that pattern-matches it becomes a
/// compile error — which is exactly the migration signal we want.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ProviderInstance {
    /// Bare local provider name — `"aws"`, never `"aws.us_east_2"`.
    /// Private: [`TryFrom<String>`] is the only constructor, so the
    /// no-alias invariant holds on the deserialize path too. Plans are
    /// persisted and re-read across reconcile cycles and pod restarts,
    /// so that path is a real boundary, not a theoretical one.
    name: String,
}

impl ProviderInstance {
    /// The bare local provider name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Why a `provider = …` meta-argument could not become a
/// [`ProviderInstance`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderInstanceError {
    #[error(
        "provider reference `{0}` names an alias: magma resolves every resource to the \
         DEFAULT instance of its provider and cannot instantiate an aliased one. Applying \
         anyway would route this resource to the default provider — a different account or \
         region than declared — so it is refused rather than silently ignored."
    )]
    Aliased(String),
    #[error("empty provider reference")]
    Empty,
}

impl TryFrom<String> for ProviderInstance {
    type Error = ProviderInstanceError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(ProviderInstanceError::Empty);
        }
        if s.contains('.') {
            return Err(ProviderInstanceError::Aliased(s));
        }
        Ok(Self { name: s })
    }
}

impl From<ProviderInstance> for String {
    fn from(p: ProviderInstance) -> Self {
        p.name
    }
}

/// The executor-owned meta-arguments of one resource block, parsed out
/// of the rendered JSON so they can never be mistaken for provider
/// attributes.
///
/// Only the two magma implements live here. The remaining Terraform
/// meta-arguments (`count`, `for_each`, `lifecycle`, `provisioner`,
/// `connection`) are recognised at the config boundary and **refused**
/// there — see `magma_config::split_resource_body` — because each of
/// them is silently wrong when ignored, not merely unsupported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMeta {
    /// `provider = "aws"` — which provider instance applies this
    /// resource. `None` means "infer from the resource type's prefix",
    /// the rule magma has always used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderInstance>,
    /// `depends_on = ["aws_iam_role.x"]` — ordering the author declared
    /// explicitly, which by definition is NOT discoverable from
    /// `${…}` interpolation (that is the entire reason the
    /// meta-argument exists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<ResourceAddress>,
}

impl ResourceMeta {
    /// The meta-arguments magma implements — the two [`ResourceMeta`]
    /// has fields for.
    pub const IMPLEMENTED: [&'static str; 2] = ["provider", "depends_on"];

    /// The meta-arguments magma recognises but does not implement, paired
    /// with what silently ignoring each one would actually do. The message
    /// is the point: an operator who hits this needs to know the executor
    /// cannot honour what they wrote, not merely that a key was rejected.
    pub const UNIMPLEMENTED: [(&'static str, &'static str); 5] = [
        (
            "count",
            "Ignoring it would create ONE resource where N were declared.",
        ),
        (
            "for_each",
            "Ignoring it would create ONE resource where one per element was declared.",
        ),
        (
            "lifecycle",
            "Ignoring it would discard `prevent_destroy`, `ignore_changes` and \
             `create_before_destroy` — a `prevent_destroy` resource could be destroyed.",
        ),
        (
            "provisioner",
            "Ignoring it would report success for a resource whose provisioning steps never ran.",
        ),
        (
            "connection",
            "Ignoring it would discard the connection settings its provisioners require.",
        ),
    ];

    /// Is `key` a meta-argument — implemented or not?
    ///
    /// **The catalog is CLOSED and lives here, in one place, because two
    /// independent doors now enforce it.** `magma_config::split_resource_body`
    /// enforces it while parsing Terraform JSON; [`Resource::new`] enforces it
    /// while a Rust front end constructs a node directly. Two copies of the
    /// list would mean a meta-argument could be closed on one door and open on
    /// the other — which is the *same* class of defect as the one the split
    /// exists to fix, just relocated.
    #[must_use]
    pub fn is_meta_key(key: &str) -> bool {
        Self::IMPLEMENTED.contains(&key) || Self::UNIMPLEMENTED.iter().any(|(k, _)| *k == key)
    }

    /// True when the block declared no meta-arguments at all — the
    /// common case, and the one that serializes to nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.depends_on.is_empty()
    }
}

// ── Declared resource ──────────────────────────────────────────────

/// Why a [`Resource`] could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceError {
    /// A meta-argument was found among the provider attributes.
    #[error(
        "resource `{address}`: `{key}` is a meta-argument, not a provider attribute. \
         It belongs on `Resource::meta` (a typed `ResourceMeta`), where magma can act \
         on it. Left in the attributes it would be handed to the provider encoder, \
         which walks the provider SCHEMA and drops unknown keys without complaint — \
         so it would evaporate silently and still count as declared drift."
    )]
    MetaArgumentInAttributes { address: String, key: String },
}

/// One resource as **declared** — the config-side peer of
/// [`StateResource`] (what the world holds) and [`ResourceChange`] (what
/// a plan intends to do about the difference).
///
/// **This is the typed door into magma.** Until it existed, the only way
/// to hand magma a resource was `magma_config::Config`, whose
/// `resources` field is a `HashMap<String, HashMap<String, Value>>` —
/// a transliteration of Terraform JSON in which identity, provider
/// routing and ordering are all *strings inside an untyped body*. A
/// front end in another dialect (a blue `(definfra …)` form) therefore
/// had to emit Terraform JSON text and have magma parse it back, which
/// makes the JSON surface load-bearing for a language that has no reason
/// to know it exists.
///
/// A `Resource` carries the three facts that are magma's, not the
/// provider's, as typed values:
///
/// * `address` — [`ResourceAddress`], not `"aws_vpc" → "main"` map keys.
/// * `meta.provider` — [`ProviderInstance`], which structurally cannot
///   hold an alias.
/// * `meta.depends_on` — `Vec<ResourceAddress>`, not a list of strings
///   that has to be re-parsed to become a graph edge.
///
/// **What stays JSON, and why that is not a gap.** `attributes` is a
/// `serde_json::Value` because attribute *values* are cty data shaped by
/// the provider's own schema, which magma only learns at runtime over
/// the plugin protocol. They are data, not Terraform syntax; typing them
/// would mean generating a Rust type per resource type per provider
/// version. The JSON here is the same JSON `magma_cty` already encodes
/// against a schema — no text is parsed and none is emitted.
///
/// **The one invariant.** `attributes` may not contain a meta-argument
/// key. The field is private and [`Resource::new`] is the only
/// constructor, so a `Resource` holding `provider` or `depends_on` among
/// its attributes has no code path in safe Rust — including through
/// `Deserialize`, which routes through the same check. Tier-honest: the
/// *value* is rejected at the construction boundary (a `Result::Err`,
/// i.e. parse-time-rejected), while the *state* of holding one is
/// unrepresentable because nothing can write the field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "ResourceRepr", try_from = "ResourceRepr")]
pub struct Resource {
    /// Canonical identity — kind, module, type, name, instance key.
    pub address: ResourceAddress,
    /// The executor-owned meta-arguments, typed.
    pub meta: ResourceMeta,
    /// Provider attributes ONLY. Private: see the type doc.
    attributes: serde_json::Value,
}

/// Serialization shadow for [`Resource`], so the private `attributes`
/// field round-trips through the same validation the constructor
/// applies. A plan or a declaration read back from disk is a real
/// boundary — the same reason [`ProviderInstance`] takes this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceRepr {
    address: ResourceAddress,
    #[serde(default)]
    meta: ResourceMeta,
    #[serde(default)]
    attributes: serde_json::Value,
}

impl From<Resource> for ResourceRepr {
    fn from(r: Resource) -> Self {
        Self {
            address: r.address,
            meta: r.meta,
            attributes: r.attributes,
        }
    }
}

impl TryFrom<ResourceRepr> for Resource {
    type Error = ResourceError;
    fn try_from(r: ResourceRepr) -> Result<Self, Self::Error> {
        Self::new(r.address, r.attributes).map(|res| res.with_meta(r.meta))
    }
}

impl Resource {
    /// Declare a resource from its address and its provider attributes.
    ///
    /// Refuses any attribute whose key is a meta-argument
    /// ([`ResourceMeta::is_meta_key`]) — that is the whole invariant this
    /// constructor exists to hold. A non-object `attributes` is accepted
    /// unchanged and carries no keys to check, matching what
    /// `magma_config::split_resource_body` already tolerates on the JSON
    /// door; the shape is handled (loudly) further downstream and is not
    /// this constructor's to reinterpret.
    pub fn new(
        address: ResourceAddress,
        attributes: serde_json::Value,
    ) -> Result<Self, ResourceError> {
        if let Some(obj) = attributes.as_object() {
            for key in obj.keys() {
                if ResourceMeta::is_meta_key(key) {
                    return Err(ResourceError::MetaArgumentInAttributes {
                        address: address.to_string(),
                        key: key.clone(),
                    });
                }
            }
        }
        Ok(Self {
            address,
            meta: ResourceMeta::default(),
            attributes,
        })
    }

    /// Attach the full typed meta block.
    #[must_use]
    pub fn with_meta(mut self, meta: ResourceMeta) -> Self {
        self.meta = meta;
        self
    }

    /// Route this resource through a named provider instance.
    #[must_use]
    pub fn with_provider(mut self, provider: ProviderInstance) -> Self {
        self.meta.provider = Some(provider);
        self
    }

    /// Declare ordering that no interpolation expresses — the entire
    /// reason `depends_on` exists.
    #[must_use]
    pub fn depending_on(mut self, deps: impl IntoIterator<Item = ResourceAddress>) -> Self {
        self.meta.depends_on.extend(deps);
        self
    }

    /// The provider attributes. Read-only by construction.
    #[must_use]
    pub fn attributes(&self) -> &serde_json::Value {
        &self.attributes
    }

    /// Take the provider attributes, consuming the resource.
    #[must_use]
    pub fn into_attributes(self) -> serde_json::Value {
        self.attributes
    }

    /// This resource as an edge-derivation node.
    #[must_use]
    pub fn dependency_node(&self) -> DependencyNode<'_> {
        DependencyNode {
            address: &self.address,
            depends_on: &self.meta.depends_on,
            body: Some(&self.attributes),
        }
    }
}

// ── Dependency-edge inputs ─────────────────────────────────────────

/// The three facts dependency-edge derivation needs from a node,
/// borrowed. Consumed by `magma_config::dependency_edges`, which owns
/// the derivation itself (it needs the `${…}` scanner that lives with
/// the rest of the interpolation family).
///
/// A borrowed VIEW rather than a concrete type, because the two node
/// populations that need edges are different types at different stages:
/// a declared [`Resource`] (config-time, what a front end builds) and a
/// [`ResourceChange`] (plan-time, what the apply engine orders).
/// Converting one into the other to share the derivation would clone
/// every resource body on magma's hottest path; this view clones
/// nothing, so there is no reason left to keep two copies of the
/// derivation — which is how a missing edge source once existed in both
/// and was fixed in neither.
#[derive(Debug, Clone, Copy)]
pub struct DependencyNode<'a> {
    /// Who this node is.
    pub address: &'a ResourceAddress,
    /// Ordering the author declared explicitly.
    pub depends_on: &'a [ResourceAddress],
    /// The body to scan for `${type.name.attr}` references. `None` for a
    /// node with no config body left — a delete.
    pub body: Option<&'a serde_json::Value>,
}

/// One `dependent depends on dependency` edge: `dependency` must be
/// applied before `dependent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEdge {
    pub dependent: ResourceAddress,
    pub dependency: ResourceAddress,
}

impl ResourceChange {
    /// This planned change as an edge-derivation node. The body scanned
    /// is `after` — the desired config, which still carries its literal
    /// `${…}` references at this stage (`magma_plan` deliberately leaves
    /// them unresolved so these edges survive).
    #[must_use]
    pub fn dependency_node(&self) -> DependencyNode<'_> {
        DependencyNode {
            address: &self.address,
            depends_on: &self.meta.depends_on,
            body: self.after.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub reasons: Vec<ChangeReason>,
    /// Meta-arguments declared on this resource's config block.
    ///
    /// `#[serde(default)]` so a plan persisted before this field existed
    /// still deserializes — an in-flight plan artifact must not become
    /// unreadable across a magma upgrade. An old plan reads back with
    /// empty meta, which is exactly the behaviour it was built under.
    #[serde(default, skip_serializing_if = "ResourceMeta::is_empty")]
    pub meta: ResourceMeta,
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

    // ── Provider instance ──────────────────────────────────────────
    //
    // `ProviderReference.alias` has been a field on a real type since
    // M0 and was read on NO apply path: provider selection was
    // `type_id.split('_').next()` and nothing else. A resource declaring
    // `provider = "aws.us_east_2"` was therefore applied through the
    // DEFAULT `aws` provider — real infrastructure in the wrong account,
    // reported as success.

    #[test]
    fn an_aliased_provider_reference_is_refused_rather_than_resolved_to_the_default() {
        let err = ProviderInstance::try_from("aws.us_east_2".to_string())
            .expect_err("an aliased provider reference must not resolve");
        assert_eq!(err, ProviderInstanceError::Aliased("aws.us_east_2".into()));
        // The message has to say WHY, because the operator's next move
        // depends on knowing magma silently used a different account.
        assert!(
            err.to_string().contains("account or region"),
            "the refusal must name the consequence it prevents, got: {err}"
        );
    }

    #[test]
    fn a_bare_provider_reference_resolves_to_that_provider() {
        let p = ProviderInstance::try_from("aws".to_string()).expect("a bare name is valid");
        assert_eq!(p.name(), "aws");
    }

    #[test]
    fn an_empty_provider_reference_is_refused() {
        assert_eq!(
            ProviderInstance::try_from(String::new()),
            Err(ProviderInstanceError::Empty)
        );
    }

    /// A plan is persisted and re-read across reconcile cycles and pod
    /// restarts, so deserialization is a real boundary, not a
    /// theoretical one — an alias must not be able to sneak in through
    /// it either.
    #[test]
    fn an_aliased_provider_cannot_be_deserialized_into_a_change() {
        let err = serde_json::from_str::<ProviderInstance>("\"aws.us_east_2\"")
            .expect_err("deserialization must enforce the same invariant as construction");
        assert!(
            err.to_string().contains("account or region"),
            "the typed refusal must survive the serde boundary, got: {err}"
        );
    }

    #[test]
    fn a_provider_instance_round_trips_as_a_plain_string() {
        let p = ProviderInstance::try_from("cloudflare".to_string()).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"cloudflare\"");
        assert_eq!(serde_json::from_str::<ProviderInstance>(&json).unwrap(), p);
    }

    /// An in-flight plan written before `meta` existed must still be
    /// readable — a magma upgrade must not strand a persisted plan.
    #[test]
    fn a_change_serialized_without_meta_still_deserializes() {
        let json = serde_json::json!({
            "address": {
                "module": [],
                "kind": "managed",
                "type_id": "aws_vpc",
                "name": "main",
                "key": null,
            },
            "action": "create",
            "before": null,
            "after": null,
            "reasons": [],
        });
        let c: ResourceChange = serde_json::from_value(json).expect("legacy plan must still read");
        assert!(c.meta.is_empty());
    }

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

#[cfg(test)]
mod read_is_not_a_change_tests {
    use super::*;

    fn addr(kind: ResourceKind, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind,
            type_id: ResourceTypeId("aws_vpc".into()),
            name: name.into(),
            key: None,
        }
    }

    fn plan_of(changes: Vec<ResourceChange>) -> Plan {
        Plan {
            id: PlanId([0u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::new(),
            variables: HashMap::new(),
            resource_changes: changes,
            output_changes: vec![],
            observation: Observation::default(),
        }
    }

    fn change(kind: ResourceKind, name: &str, action: Action) -> ResourceChange {
        ResourceChange {
            address: addr(kind, name),
            action,
            before: None,
            after: None,
            reasons: vec![],
            meta: ResourceMeta::default(),
        }
    }

    /// A `Read` is observation, not intent — `change_count` must exclude it.
    ///
    /// This became reachable only when `magma_plan::plan` started EMITTING
    /// `Read` for data sources (3de7bbb). Before that an unread data source
    /// came out as `Create`, so "non-NoOp" was an accurate proxy for "intends
    /// to change" everywhere in the codebase. Making data sources honest turned
    /// that proxy false — and the failure was not theoretical: the
    /// example-eks-vpn-concentrator apply died on
    /// `assert_apply_converges` with "re-plan has 4 non-NoOp changes", all four
    /// being `kind: Data, action: Read`. A workspace with a `data` block could
    /// never converge, because a data source has no state row to settle into
    /// and is re-read on every plan by definition.
    #[test]
    fn change_count_excludes_reads_and_noops() {
        let p = plan_of(vec![
            change(ResourceKind::Managed, "real", Action::Create),
            change(ResourceKind::Managed, "settled", Action::NoOp),
            change(ResourceKind::Data, "lookup_a", Action::Read),
            change(ResourceKind::Data, "lookup_b", Action::Read),
        ]);
        assert_eq!(
            p.change_count(),
            1,
            "only the managed Create is an intended change; NoOp and Read are not"
        );
    }

    /// The inverse guard: a data ORPHAN (in state, gone from config) IS pending
    /// work — it must be dropped from state — so Delete stays counted. Without
    /// this, "exclude data sources" could be over-applied by kind and silently
    /// hide a real removal.
    #[test]
    fn a_data_orphan_delete_still_counts_as_a_change() {
        let p = plan_of(vec![
            change(ResourceKind::Data, "orphan", Action::Delete),
            change(ResourceKind::Data, "live", Action::Read),
        ]);
        assert_eq!(
            p.change_count(),
            1,
            "a data orphan's Delete is real pending work; only Read is not"
        );
    }

    // ── Resource: the typed declaration node ───────────────────────
    //
    // The whole point of the type is that a meta-argument cannot hide in
    // the attributes. Downstream, `magma_cty::from_json` walks the
    // provider SCHEMA rather than the JSON, so an unknown key is dropped
    // in silence while still counting as declared drift — a resource
    // applied through the wrong provider, re-planning as Update forever,
    // and no error anywhere. The JSON door closed that at parse time;
    // this closes it at construction time, so the new door cannot reopen
    // it.

    fn res_addr(type_id: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_id.to_string()),
            name: name.to_string(),
            key: None,
        }
    }

    #[test]
    fn every_meta_argument_in_the_closed_catalog_is_refused_in_the_attributes() {
        // Drive the test FROM the catalog, so a meta-argument added to
        // `ResourceMeta` without being closed on this door fails here
        // rather than shipping open.
        let keys: Vec<&str> = ResourceMeta::IMPLEMENTED
            .iter()
            .copied()
            .chain(ResourceMeta::UNIMPLEMENTED.iter().map(|(k, _)| *k))
            .collect();
        assert_eq!(keys.len(), 7, "the catalog changed — check both doors");

        for key in keys {
            let attrs = serde_json::json!({ key: "whatever" });
            let err = Resource::new(res_addr("aws_instance", "web"), attrs)
                .expect_err("a meta-argument is not a provider attribute");
            assert_eq!(
                err,
                ResourceError::MetaArgumentInAttributes {
                    address: "aws_instance.web".to_string(),
                    key: key.to_string(),
                }
            );
            // The message has to say where it belongs, or the caller's
            // next move is a guess.
            assert!(
                err.to_string().contains("Resource::meta"),
                "the refusal must name the typed home, got: {err}"
            );
        }
    }

    /// Deserialize is a real boundary — a declaration is persisted and
    /// read back — so it routes through the same constructor rather than
    /// filling the private field directly.
    #[test]
    fn deserializing_a_resource_with_a_meta_argument_in_its_attributes_is_refused() {
        let raw = serde_json::json!({
            "address": res_addr("aws_instance", "web"),
            "attributes": { "ami": "ami-1", "depends_on": ["aws_iam_role.exec"] }
        });
        let err = serde_json::from_value::<Resource>(raw)
            .expect_err("the private field must not be reachable through serde");
        assert!(
            err.to_string().contains("depends_on"),
            "the deserialize error must name the offending key, got: {err}"
        );
    }

    #[test]
    fn a_resource_round_trips_through_serde_with_its_typed_meta_intact() {
        let r = Resource::new(
            res_addr("aws_instance", "web"),
            serde_json::json!({"ami": "ami-1"}),
        )
        .expect("valid")
        .with_provider(ProviderInstance::try_from("aws".to_string()).expect("bare"))
        .depending_on([res_addr("aws_iam_role", "exec")]);
        let back: Resource =
            serde_json::from_value(serde_json::to_value(&r).expect("serializes")).expect("parses");
        assert_eq!(back, r);
    }

    /// Matches what `magma_config::split_resource_body` already tolerates
    /// on the JSON door: a non-object body is passed through, because the
    /// shape is handled (loudly) downstream and carries no keys to check.
    #[test]
    fn a_non_object_attribute_body_is_accepted_unchanged() {
        let r = Resource::new(res_addr("aws_instance", "web"), serde_json::json!("opaque"))
            .expect("no keys to check");
        assert_eq!(*r.attributes(), serde_json::json!("opaque"));
    }

    #[test]
    fn a_declared_resources_dependency_node_carries_both_edge_sources() {
        let r = Resource::new(
            res_addr("aws_subnet", "a"),
            serde_json::json!({ "vpc_id": "${aws_vpc.main.id}" }),
        )
        .expect("valid")
        .depending_on([res_addr("aws_iam_role", "exec")]);
        let node = r.dependency_node();
        assert_eq!(node.address, &res_addr("aws_subnet", "a"));
        assert_eq!(node.depends_on, &[res_addr("aws_iam_role", "exec")]);
        assert_eq!(node.body, Some(r.attributes()));
    }
}
