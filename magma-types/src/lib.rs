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
pub mod reference;

pub use observation::{Coverage, DriftVerdict, Observation, ObservationError, RefreshCounts};
pub use reference::{
    AttrError, AttrStep, AttrValue, Ref, RefError, TextPart, collect_refs, ref_target,
};

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

/// The provider instance a resource is applied through — one
/// `provider "<name>" {}` block, and the `alias` (if any) that
/// distinguishes it from its siblings.
///
/// **This is the identity, and therefore the KEY.** A provider instance
/// is `(name, alias)` — two structured components, never one flattened
/// `"aws.us_east_2"` string. `magma_config::Config::providers`,
/// `ApplyContext::provider_configs` and the apply `Registry` are all
/// keyed by this value, so "which provider instance" is looked up, never
/// re-parsed. A string key would put the `name`/`alias` split back into
/// every consumer, which is exactly the parsing this arc has been
/// removing: `5b159e3` made references typed for that reason, and
/// `AttrStep` was chosen over `Vec<String>` because a path spelled as a
/// string carries brackets.
///
/// The string form exists only at the two text boundaries — the
/// `provider = "aws.us_east_2"` meta-argument in rendered Terraform JSON
/// and the serde wire — and both go through exactly one parser
/// ([`TryFrom<String>`](#impl-TryFrom<String>-for-ProviderInstance)) and
/// one renderer ([`Display`](#impl-Display-for-ProviderInstance)).
///
/// **What is and is not proven.** The grammar is enforced at
/// construction *and* deserialization: a name or alias containing a `.`,
/// or more than two segments, has no representation, because the fields
/// are private and every constructor rejects them. A *declared* instance
/// that no `provider` block configures is a different matter — that is a
/// `Result::Err` at the config boundary
/// (`magma_config::ConfigError::UndeclaredProviderInstance`) and at dial
/// time (`magma_apply::engine::EngineError::UnconfiguredProviderAlias`),
/// i.e. **only mitigation**, not impossibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ProviderInstance {
    /// Bare local provider name — `"aws"`. Never contains a `.`.
    /// Private: every constructor validates, so the grammar holds on the
    /// deserialize path too. Plans are persisted and re-read across
    /// reconcile cycles and pod restarts, so that path is a real
    /// boundary, not a theoretical one.
    name: String,
    /// The `alias = "…"` of the `provider` block this instance names.
    /// `None` is the DEFAULT instance — the one a resource declaring no
    /// `provider` meta-argument resolves to. Never contains a `.`.
    ///
    /// Ordered after `name` by the derived `Ord`, so the default
    /// instance sorts before its aliased siblings (`None < Some(_)`).
    alias: Option<String>,
}

impl ProviderInstance {
    /// The bare local provider name — `"aws"` for both `aws` and
    /// `aws.us_east_2`. This is what selects the provider BINARY: every
    /// instance of one provider is served by the same plugin, configured
    /// separately.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The alias, or `None` for the default instance.
    #[must_use]
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// Is this the DEFAULT instance of its provider — the one an
    /// unqualified resource resolves to, and the one that may legitimately
    /// be dialed with no configuration block (the provider then falls back
    /// to its own environment credentials, exactly as terraform does for an
    /// absent `provider` block)?
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.alias.is_none()
    }

    /// The default instance of a provider named by a bare local name.
    pub fn default_instance(name: impl Into<String>) -> Result<Self, ProviderInstanceError> {
        let name = name.into();
        Self::check_segment(&name, Segment::Name)?;
        Ok(Self { name, alias: None })
    }

    /// A named alias of a provider — `aws` + `us_east_2`.
    pub fn aliased(
        name: impl Into<String>,
        alias: impl Into<String>,
    ) -> Result<Self, ProviderInstanceError> {
        let name = name.into();
        let alias = alias.into();
        Self::check_segment(&name, Segment::Name)?;
        Self::check_segment(&alias, Segment::Alias)?;
        Ok(Self {
            name,
            alias: Some(alias),
        })
    }

    /// The default instance of the provider a resource TYPE implies —
    /// `"github_repository"` → the default `github` instance.
    ///
    /// **Infallible by construction, and that is deliberate.** The split
    /// includes `.` as a terminator, so no dot can reach `name` however
    /// malformed the type id is — the grammar invariant is upheld here
    /// without a `Result` for a caller that structurally cannot supply an
    /// alias. The type-prefix rule itself remains a guess: `google_*`
    /// resources are served by the `google` provider, but the mapping is
    /// convention, not contract.
    #[must_use]
    pub fn implied_by_type(type_id: &str) -> Self {
        let name = type_id.split(['_', '.']).next().unwrap_or(type_id);
        Self {
            name: name.to_string(),
            alias: None,
        }
    }

    fn check_segment(s: &str, which: Segment) -> Result<(), ProviderInstanceError> {
        if s.is_empty() {
            return Err(match which {
                Segment::Name => ProviderInstanceError::Empty,
                Segment::Alias => ProviderInstanceError::EmptyAlias,
            });
        }
        if s.contains('.') {
            return Err(ProviderInstanceError::DottedSegment {
                which: which.label(),
                value: s.to_string(),
            });
        }
        Ok(())
    }
}

/// Which half of a `<name>.<alias>` reference a validation concerns.
#[derive(Debug, Clone, Copy)]
enum Segment {
    Name,
    Alias,
}

impl Segment {
    fn label(self) -> &'static str {
        match self {
            Self::Name => "provider name",
            Self::Alias => "alias",
        }
    }
}

/// Why a `provider = …` meta-argument could not become a
/// [`ProviderInstance`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderInstanceError {
    #[error("empty provider reference")]
    Empty,
    #[error("empty provider alias: `<name>.` names no provider instance")]
    EmptyAlias,
    #[error(
        "provider reference `{0}` has more than two segments: the grammar is `<name>` for a \
         provider's default instance or `<name>.<alias>` for a declared alias, and nothing else"
    )]
    TooManySegments(String),
    #[error("{which} `{value}` contains a `.`, which separates a provider name from its alias")]
    DottedSegment { which: &'static str, value: String },
}

impl TryFrom<String> for ProviderInstance {
    type Error = ProviderInstanceError;

    /// The ONE parser for the `<name>[.<alias>]` text form. Every other
    /// constructor takes the components already split, so this is the only
    /// place the grammar is read.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(ProviderInstanceError::Empty);
        }
        let mut segments = s.split('.');
        // `split` on a non-empty string always yields at least one item.
        let name = segments.next().unwrap_or(&s);
        match (segments.next(), segments.next()) {
            (None, _) => Self::default_instance(name),
            (Some(alias), None) => Self::aliased(name, alias),
            (Some(_), Some(_)) => Err(ProviderInstanceError::TooManySegments(s.clone())),
        }
    }
}

/// The ONE renderer of the text form — a `Display`-family `write!`, so no
/// syntax is `format!`ed (★★ TYPED EMISSION).
impl std::fmt::Display for ProviderInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)?;
        if let Some(alias) = &self.alias {
            f.write_str(".")?;
            f.write_str(alias)?;
        }
        Ok(())
    }
}

impl From<ProviderInstance> for String {
    fn from(p: ProviderInstance) -> Self {
        p.to_string()
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
    /// `provider = "aws"` / `provider = "aws.us_east_2"` — which provider
    /// instance applies this resource. `None` means "infer from the
    /// resource type's prefix", the rule magma has always used, which
    /// always yields a DEFAULT instance.
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
    /// The typed [`Ref`]s attached to a resource are not exactly the
    /// references its body carries.
    #[error(
        "resource `{address}`: its typed references and its body disagree. Declared \
         {declared:?}, body carries {found:?}. Edge derivation reads the TYPED references \
         for a resource that has any and does not scan its body, so a disagreement is a \
         dependency edge that is missing or invented — silently, since both halves are \
         individually well-formed. The two are the same references seen twice; they are \
         required to be equal, in body-walk order."
    )]
    RefsDoNotMatchBody {
        address: String,
        declared: Vec<String>,
        found: Vec<String>,
    },
    /// A typed attribute tree could not be lowered — see [`AttrError`].
    #[error("resource `{address}`: {source}")]
    Attr {
        address: String,
        #[source]
        source: AttrError,
    },
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
/// * `meta.provider` — [`ProviderInstance`], the typed `(name, alias)`
///   identity, not a `"aws.us_east_2"` string every consumer re-splits.
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
/// **What no longer stays JSON: references.** A value that points at
/// another resource is not provider data — it is magma's own dependency
/// structure, and it used to survive only as the literal text
/// `"${aws_vpc.main.id}"`. [`Resource::from_attrs`] takes a typed
/// [`AttrValue`] tree instead, lowers each [`Ref`] through the one
/// renderer, and keeps the references *as values* alongside the rendered
/// body. The body is unchanged in shape — the same JSON a provider
/// encoder sees — and the graph no longer has to be recovered from it by
/// scanning.
///
/// **The invariants.**
///
/// 1. `attributes` may not contain a meta-argument key. The field is
///    private and [`Resource::new`] is the only constructor, so a
///    `Resource` holding `provider` or `depends_on` among its attributes
///    has no code path in safe Rust — including through `Deserialize`,
///    which routes through the same check.
/// 2. `refs`, when non-empty, is exactly the reference set the body
///    carries, in body-walk order — `collect_refs(attributes) ==
///    refs.map(Ref::path)`. Every way to attach references
///    ([`from_attrs`](Resource::from_attrs), [`with_refs`](Resource::with_refs),
///    `Deserialize`) goes through the same check, so the typed door and
///    the JSON door cannot disagree about what this resource depends on.
///    That equality *is* the compatibility contract between the two
///    doors, enforced at construction rather than asserted in a test.
///
/// Tier-honest for both: the *value* is rejected at the construction
/// boundary (a `Result::Err`, i.e. parse-time-rejected), while the
/// *state* of holding a bad one is unrepresentable because nothing can
/// write the fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "ResourceRepr", try_from = "ResourceRepr")]
pub struct Resource {
    /// Canonical identity — kind, module, type, name, instance key.
    pub address: ResourceAddress,
    /// The executor-owned meta-arguments, typed.
    pub meta: ResourceMeta,
    /// Provider attributes ONLY. Private: see the type doc.
    attributes: serde_json::Value,
    /// The references this resource's body carries, typed. Private: see
    /// invariant 2 in the type doc.
    refs: Vec<Ref>,
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
    /// Omitted entirely when empty, so a JSON-authored resource
    /// serializes to exactly the bytes it did before typed references
    /// existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refs: Vec<Ref>,
}

impl From<Resource> for ResourceRepr {
    fn from(r: Resource) -> Self {
        Self {
            address: r.address,
            meta: r.meta,
            attributes: r.attributes,
            refs: r.refs,
        }
    }
}

impl TryFrom<ResourceRepr> for Resource {
    type Error = ResourceError;
    fn try_from(r: ResourceRepr) -> Result<Self, Self::Error> {
        Self::new(r.address, r.attributes)?
            .with_meta(r.meta)
            .with_refs(r.refs)
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
            refs: Vec::new(),
        })
    }

    /// Declare a resource from a typed attribute tree — **the door with
    /// no Terraform syntax in it at all.**
    ///
    /// [`Resource::new`] closed the structural half: address, provider
    /// and ordering stopped being strings. This closes the value half. A
    /// reference is an [`AttrValue::Ref`] over the target's own
    /// [`ResourceAddress`], lowered to `${…}` by the one renderer, and
    /// the resulting `Resource` carries those references as *values* — so
    /// the dependency graph is read off the declaration instead of
    /// recovered from its text.
    ///
    /// ```
    /// # use magma_types::{AttrValue, ModulePath, Ref, Resource, ResourceAddress, ResourceKind, ResourceTypeId};
    /// # fn a(t: &str, n: &str) -> ResourceAddress { ResourceAddress {
    /// #     module: ModulePath::root(), kind: ResourceKind::Managed,
    /// #     type_id: ResourceTypeId(t.into()), name: n.into(), key: None } }
    /// let vpc_id = Ref::new(a("aws_vpc", "main"), ["id"])?;
    /// let subnet = Resource::from_attrs(
    ///     a("aws_subnet", "a"),
    ///     AttrValue::map([
    ///         ("cidr_block", AttrValue::from("10.0.1.0/24")),
    ///         ("vpc_id", AttrValue::from(vpc_id)),
    ///     ]),
    /// )?;
    /// assert_eq!(subnet.attributes()["vpc_id"], "${aws_vpc.main.id}");
    /// assert_eq!(subnet.refs().len(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_attrs(address: ResourceAddress, attrs: AttrValue) -> Result<Self, ResourceError> {
        let (body, refs) = attrs.lower().map_err(|source| ResourceError::Attr {
            address: address.to_string(),
            source,
        })?;
        Self::new(address, body)?.with_refs(refs)
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

    /// Attach the typed references this resource's body carries.
    ///
    /// Fallible on purpose, and checked against the body: the references
    /// must be exactly the ones a scan of `attributes` finds, in the same
    /// order (invariant 2 on the type). [`Resource::from_attrs`] is the
    /// ergonomic door and cannot get this wrong — it produces both halves
    /// from one tree — but a front end that renders its own JSON can
    /// still hand its references over here and have the claim checked
    /// rather than trusted.
    ///
    /// Passing an empty list is always accepted and means "this resource
    /// was authored as JSON; derive its edges by scanning".
    pub fn with_refs(mut self, refs: Vec<Ref>) -> Result<Self, ResourceError> {
        if !refs.is_empty() {
            let found = reference::collect_refs(&self.attributes);
            let declared: Vec<String> = refs.iter().map(Ref::path).collect();
            if found != declared {
                return Err(ResourceError::RefsDoNotMatchBody {
                    address: self.address.to_string(),
                    declared,
                    found,
                });
            }
        }
        self.refs = refs;
        Ok(self)
    }

    /// The provider attributes. Read-only by construction.
    #[must_use]
    pub fn attributes(&self) -> &serde_json::Value {
        &self.attributes
    }

    /// The typed references this resource's body carries. Empty for a
    /// JSON-authored resource, whose references live only as text and are
    /// recovered by scanning.
    #[must_use]
    pub fn refs(&self) -> &[Ref] {
        &self.refs
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
            refs: &self.refs,
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
    /// The body to scan for `${type.name.attr}` references — the
    /// COMPATIBILITY source, used only when `refs` is empty. `None` for a
    /// node with no config body left — a delete.
    pub body: Option<&'a serde_json::Value>,
    /// The references this node carries as typed values — the STRUCTURAL
    /// source. When non-empty these are the node's interpolation edges
    /// and `body` is not scanned: the answer is already known, so there
    /// is nothing to re-derive from text. A [`Resource`] guarantees the
    /// two say the same thing (invariant 2 on that type), which is why
    /// choosing one is safe rather than a preference.
    pub refs: &'a [Ref],
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
    ///
    /// **A change carries no typed references, deliberately.** A plan is
    /// computed against a `magma_config::Config`, whose container is
    /// Terraform-JSON-shaped: a reference survives it as the rendered
    /// string and nothing else. So the apply-time graph takes the
    /// compatibility path, and it gets the same edges the typed path
    /// would — that equality is what `Resource`'s invariant 2 guarantees.
    /// Carrying references down to here would mean threading a side
    /// channel through the plan for an answer that is already correct;
    /// the honest place for the structural path is config time, where the
    /// declaration still exists.
    #[must_use]
    pub fn dependency_node(&self) -> DependencyNode<'_> {
        DependencyNode {
            address: &self.address,
            depends_on: &self.meta.depends_on,
            body: self.after.as_ref(),
            refs: &[],
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
    // reported as success. `2e418ca` made that a refusal; this type now
    // carries the alias as a typed component so the declaration can
    // actually be honoured.

    #[test]
    fn an_aliased_provider_reference_parses_into_its_two_components() {
        let p = ProviderInstance::try_from("aws.us_east_2".to_string())
            .expect("an aliased reference is a valid provider instance");
        assert_eq!(p.name(), "aws");
        assert_eq!(p.alias(), Some("us_east_2"));
        assert!(!p.is_default());
    }

    #[test]
    fn a_bare_provider_reference_resolves_to_that_provider() {
        let p = ProviderInstance::try_from("aws".to_string()).expect("a bare name is valid");
        assert_eq!(p.name(), "aws");
        assert_eq!(p.alias(), None);
        assert!(p.is_default());
    }

    #[test]
    fn an_empty_provider_reference_is_refused() {
        assert_eq!(
            ProviderInstance::try_from(String::new()),
            Err(ProviderInstanceError::Empty)
        );
    }

    /// The grammar is `<name>` or `<name>.<alias>`. A third segment is
    /// not a deeper qualification magma is ignoring — it is not a
    /// provider reference at all, and accepting it would silently bind
    /// the resource to `aws.us_east_2` while the author wrote something
    /// else.
    #[test]
    fn a_three_segment_provider_reference_is_refused() {
        assert_eq!(
            ProviderInstance::try_from("aws.us_east_2.extra".to_string()),
            Err(ProviderInstanceError::TooManySegments(
                "aws.us_east_2.extra".into()
            ))
        );
    }

    #[test]
    fn a_trailing_dot_is_refused_rather_than_read_as_the_default_instance() {
        assert_eq!(
            ProviderInstance::try_from("aws.".to_string()),
            Err(ProviderInstanceError::EmptyAlias)
        );
    }

    /// The components are private and every constructor validates, so a
    /// dot cannot enter either half by the back door — which is what
    /// keeps `Display` ⇄ `TryFrom` a bijection.
    #[test]
    fn a_dot_cannot_be_smuggled_into_either_component() {
        assert!(matches!(
            ProviderInstance::aliased("aws", "us.east.2"),
            Err(ProviderInstanceError::DottedSegment { .. })
        ));
        assert!(matches!(
            ProviderInstance::default_instance("aws.us_east_2"),
            Err(ProviderInstanceError::DottedSegment { .. })
        ));
        // …and the type-implied constructor, which takes no `Result`,
        // terminates on `.` for exactly this reason.
        assert_eq!(ProviderInstance::implied_by_type("aws.weird").name(), "aws");
    }

    #[test]
    fn the_type_prefix_rule_yields_the_default_instance() {
        let p = ProviderInstance::implied_by_type("github_repository");
        assert_eq!(p.name(), "github");
        assert!(p.is_default());
        assert_eq!(
            ProviderInstance::implied_by_type("noprefix").name(),
            "noprefix"
        );
    }

    /// A plan is persisted and re-read across reconcile cycles and pod
    /// restarts, so deserialization is a real boundary, not a
    /// theoretical one — the grammar must hold through it too.
    #[test]
    fn an_aliased_provider_survives_the_serde_boundary_intact() {
        let p: ProviderInstance = serde_json::from_str("\"aws.us_east_2\"")
            .expect("deserialization uses the same parser as construction");
        assert_eq!(p, ProviderInstance::aliased("aws", "us_east_2").unwrap());
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"aws.us_east_2\"");
        // …and the malformed forms are refused there too.
        assert!(serde_json::from_str::<ProviderInstance>("\"a.b.c\"").is_err());
    }

    /// **Byte-identity for the unaliased case.** Every provider instance
    /// magma has ever written to a persisted plan is unaliased; its wire
    /// form must be exactly the bare name it was before `alias` existed.
    #[test]
    fn a_provider_instance_round_trips_as_a_plain_string() {
        let p = ProviderInstance::try_from("cloudflare".to_string()).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"cloudflare\"");
        assert_eq!(serde_json::from_str::<ProviderInstance>(&json).unwrap(), p);
    }

    /// The default instance sorts before its aliased siblings, so a
    /// `BTreeMap` keyed by instance iterates default-first per provider —
    /// the order every diagnostic and serialization reads.
    #[test]
    fn the_default_instance_orders_before_its_aliases() {
        let mut v = vec![
            ProviderInstance::aliased("aws", "us_east_2").unwrap(),
            ProviderInstance::default_instance("aws").unwrap(),
            ProviderInstance::aliased("aws", "eu_west_1").unwrap(),
        ];
        v.sort();
        assert_eq!(
            v.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["aws", "aws.eu_west_1", "aws.us_east_2"]
        );
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

    // ── Typed references on a declared resource ────────────────────

    fn managed(type_id: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_id.to_string()),
            name: name.to_string(),
            key: None,
        }
    }

    /// The typed door renders the reference into the body AND keeps it as
    /// a value — the body a provider encoder sees is unchanged, and the
    /// dependency is no longer only inferable from that body's text.
    #[test]
    fn a_typed_attribute_tree_renders_the_body_and_keeps_the_reference() {
        let vpc_id = Ref::new(managed("aws_vpc", "main"), ["id"]).expect("referenceable");
        let subnet = Resource::from_attrs(
            managed("aws_subnet", "a"),
            AttrValue::map([
                ("cidr_block", AttrValue::from("10.0.1.0/24")),
                ("vpc_id", AttrValue::from(vpc_id.clone())),
            ]),
        )
        .expect("valid");

        assert_eq!(
            *subnet.attributes(),
            serde_json::json!({
                "cidr_block": "10.0.1.0/24",
                "vpc_id": "${aws_vpc.main.id}",
            })
        );
        assert_eq!(subnet.refs(), [vpc_id]);
        assert_eq!(subnet.dependency_node().refs.len(), 1);
    }

    /// A JSON-authored resource carries no typed references — its edges
    /// come from the scan, exactly as before. Nothing about the second
    /// door changes the first.
    #[test]
    fn a_json_authored_resource_carries_no_typed_references() {
        let subnet = Resource::new(
            managed("aws_subnet", "a"),
            serde_json::json!({ "vpc_id": "${aws_vpc.main.id}" }),
        )
        .expect("valid");
        assert!(subnet.refs().is_empty());
        assert!(subnet.dependency_node().refs.is_empty());
    }

    /// Invariant 2, enforced. Attaching references that are not exactly
    /// the ones the body carries is refused — because edge derivation
    /// believes the typed half and would silently produce the wrong
    /// graph.
    #[test]
    fn references_that_do_not_match_the_body_are_refused() {
        let vpc_id = Ref::new(managed("aws_vpc", "main"), ["id"]).expect("referenceable");

        // Declared but absent from the body.
        let err = Resource::new(managed("aws_subnet", "a"), serde_json::json!({ "x": 1 }))
            .expect("valid")
            .with_refs(vec![vpc_id.clone()])
            .expect_err("the body carries no such reference");
        assert!(
            matches!(err, ResourceError::RefsDoNotMatchBody { .. }),
            "{err}"
        );

        // Present in the body but only half-declared.
        let err = Resource::new(
            managed("aws_subnet", "a"),
            serde_json::json!({
                "a": "${aws_vpc.main.id}",
                "b": "${aws_internet_gateway.gw.id}",
            }),
        )
        .expect("valid")
        .with_refs(vec![vpc_id])
        .expect_err("one declared, two in the body");
        assert!(
            matches!(err, ResourceError::RefsDoNotMatchBody { .. }),
            "{err}"
        );
    }

    /// A declaration is persisted and re-read, so the invariant has to
    /// survive serde — the same reason `ProviderInstance` is checked
    /// there.
    #[test]
    fn references_inconsistent_with_the_body_cannot_be_deserialized() {
        let good = Resource::from_attrs(
            managed("aws_subnet", "a"),
            AttrValue::map([(
                "vpc_id",
                AttrValue::from(Ref::new(managed("aws_vpc", "main"), ["id"]).expect("valid")),
            )]),
        )
        .expect("valid");

        let mut v = serde_json::to_value(&good).expect("serializes");
        assert_eq!(
            serde_json::from_value::<Resource>(v.clone()).expect("valid"),
            good
        );

        // Repoint the body at a different resource, leaving the typed
        // reference behind — the shape a hand-edited plan would have.
        v["attributes"]["vpc_id"] = serde_json::json!("${aws_vpc.other.id}");
        let err = serde_json::from_value::<Resource>(v).expect_err("body and refs disagree");
        assert!(
            err.to_string().contains("disagree"),
            "the refusal must survive the serde boundary, got: {err}"
        );
    }

    /// A resource with no typed references serializes to exactly the
    /// bytes it did before they existed — the field is omitted, not
    /// written as an empty list.
    #[test]
    fn a_resource_without_typed_references_serializes_unchanged() {
        let r = Resource::new(
            managed("aws_vpc", "main"),
            serde_json::json!({ "cidr": "10/8" }),
        )
        .expect("valid");
        let v = serde_json::to_value(&r).expect("serializes");
        let keys: Vec<&String> = v.as_object().expect("an object").keys().collect();
        assert_eq!(keys, ["address", "attributes", "meta"]);
    }

    /// A literal interpolation cannot be smuggled through the typed door
    /// as a plain string — that is what makes "this resource's references
    /// are exactly these values" true rather than hopeful.
    #[test]
    fn a_reference_spelled_as_text_is_refused_by_the_typed_door() {
        let err = Resource::from_attrs(
            managed("aws_subnet", "a"),
            AttrValue::map([("vpc_id", AttrValue::from("${aws_vpc.main.id}"))]),
        )
        .expect_err("a reference spelled as a string");
        assert!(matches!(err, ResourceError::Attr { .. }), "{err}");
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
