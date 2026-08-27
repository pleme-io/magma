//! The provider CONTRACT — what magma requires of *a provider*, with no
//! commitment to how one is reached.
//!
//! ── ★ WHY THIS CRATE EXISTS ──────────────────────────────────────────
//! Until now the contract was implicit: `magma-apply` held a concrete
//! `magma_plugin::provider::ProviderConn` and called inherent methods on
//! it. That bound the engine to ONE transport — a Go subprocess speaking
//! tfplugin5/6 over go-plugin — and the binding was invisible, because a
//! concrete type never announces that it is a choice.
//!
//! It is a choice, and an expensive one. Measured on the operator image
//! (r349, trivy artifact 9648954592): the Rust binary scans **0**, while
//! the 8 baked Go provider binaries carry **190 findings / 49 unique
//! ids**. The largest single contributor is `terraform-provider-random`
//! at 36 — a provider that makes no network calls at all.
//!
//! So the contract is named here, in a crate that depends on `magma-cty`
//! and NOTHING ELSE. A provider is 8 methods over cty values. gRPC is one
//! implementation of them; a native Rust provider is another, and needs
//! no tonic, no subprocess, and no Go.
//!
//! ── WHAT LIVES HERE, AND WHY IT MOVED ────────────────────────────────
//! `ProviderSchema`, `PlannedChange`, `Diag`, `Severity`, `ProviderError`
//! and `SchemaError` were defined in `magma-plugin`. They are the
//! protocol's DATA MODEL, not its transport, and leaving them next to the
//! tonic client made the dependency edge point the wrong way: the trait
//! crate would have had to depend on the gRPC crate that implements it —
//! a cycle cargo rejects outright.
//!
//! They are moved verbatim, and `magma-plugin` re-exports every one of
//! them, so every existing `magma_plugin::provider::ProviderError` path
//! still resolves. This is a relocation, not a redesign.

use std::collections::BTreeMap;

use magma_cty::{CtyType, DynamicValue};

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("attribute {0:?} has neither a type nor a nested_type")]
    AttributeNoType(String),
    #[error("cty type decode for {0:?}: {1}")]
    Cty(String, magma_cty::CtyError),
    #[error("invalid nesting mode {0} for {1:?}")]
    BadNesting(i32, String),
    #[error("nested block {0:?} has no inner block")]
    EmptyNestedBlock(String),
}

/// A provider's schema reduced to the implied cty types the apply codec
/// needs: the provider-config type + each managed resource's type.
#[derive(Debug, Clone)]
pub struct ProviderSchema {
    pub provider_config: CtyType,
    pub resources: BTreeMap<String, CtyType>,
    /// Data-source implied types (`data.<type>`), needed to encode a
    /// ReadDataSource config + decode its result. Without these the apply
    /// engine cannot evaluate `${data.*}` references (the rio-drive leak).
    pub data_sources: BTreeMap<String, CtyType>,
    /// Each managed resource type's CURRENT schema version, as declared by
    /// the provider's `GetProviderSchema`/`GetSchema` response (the
    /// `Schema.version` field sibling to the `Schema.block` that
    /// `crate::schema::block_implied_type` turns into `resources`'
    /// implied types). The terraform plugin protocol requires
    /// `UpgradeResourceState` to run whenever a stored `StateInstance`'s
    /// `schema_version` is older than this — otherwise its raw attribute
    /// JSON (persisted under the OLD schema) gets decoded straight against
    /// the NEW implied type, which a schema change can silently
    /// misinterpret or fail to marshal. See
    /// `ProviderConn::upgrade_resource_state` + `ProviderSchema::resource_version`.
    pub resource_versions: BTreeMap<String, i64>,
}

impl ProviderSchema {
    pub fn resource(&self, type_name: &str) -> Option<&CtyType> {
        self.resources.get(type_name)
    }

    pub fn data_source(&self, type_name: &str) -> Option<&CtyType> {
        self.data_sources.get(type_name)
    }

    /// The provider's CURRENT schema version for `type_name`. `0` both for
    /// a genuinely version-0 schema AND for a type the provider never
    /// declared — matching Terraform's own convention that an
    /// un-versioned schema is version 0, so an unknown type never looks
    /// artificially "newer" than a stored instance and never triggers a
    /// spurious upgrade.
    #[must_use]
    pub fn resource_version(&self, type_name: &str) -> i64 {
        self.resource_versions.get(type_name).copied().unwrap_or(0)
    }

    /// `Self::resource_version` clamped into `magma_types::StateInstance`'s
    /// `u64` `schema_version` field. Real provider schema versions are
    /// always small non-negative integers in practice; this only differs
    /// from the wire `i64` for a malformed negative version (never
    /// observed from a real provider), which clamps to `0` rather than
    /// wrapping to a huge `u64`.
    #[must_use]
    pub fn resource_version_u64(&self, type_name: &str) -> u64 {
        u64::try_from(self.resource_version(type_name)).unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
}

/// The provider's full response to `PlanResourceChange`: the normalized
/// planned state PLUS the attribute paths the provider says force a
/// destroy+create instead of an in-place update ("requires replace").
///
/// Terraform core reads this exact signal — computed by the provider
/// inside this SAME RPC — to decide Update vs Replace; it is not
/// something the schema or config can determine on their own (a
/// provider's `ForceNew` decision can be dynamic, e.g. via
/// `CustomizeDiff`). Prior to this type existing, `ProviderConn::plan_resource_change`
/// returned only the bare planned `DynamicValue`, silently discarding
/// `requires_replace` — the ONE authoritative signal a provider gives
/// for immutable/ForceNew attributes — before it ever reached
/// magma-apply's business logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub state: DynamicValue,
    /// Provider-reported attribute paths requiring replace, rendered as
    /// dotted diagnostic strings (`"instance_types"`, `"tags.name"`,
    /// `"rules[2].port"`). Empty ⇒ the provider says an in-place update
    /// is sufficient. Diagnostic-only shape: callers only need to know
    /// whether this is non-empty to trigger destroy+create orchestration
    /// (see `magma-apply::engine::apply_one`); the strings make
    /// `requires_replace` legible in logs/errors without threading a
    /// full typed attribute-path AST through every consumer.
    pub requires_replace: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider RPC transport: {0}")]
    Transport(String),
    #[error("provider returned {} error diagnostic(s): {}", .0.len(), fmt_diags(.0))]
    Diagnostics(Vec<Diag>),
    #[error("provider returned no new_state from apply")]
    NoNewState,
    /// The provider returned an error diagnostic AND a `new_state` — the
    /// resource IS (at least partially) committed provider-side.
    ///
    /// This is not a rare edge: it is how the tfplugin contract expresses a
    /// partial apply, and how Terraform core knows to persist a
    /// half-created resource. AWS EIP is the canonical shape —
    /// `AllocateAddress` commits, a follow-up call (tagging, association, the
    /// post-create read) fails, and the provider returns the allocation id
    /// together with an error.
    ///
    /// Before this variant existed, `check_diags(...)?` ran BEFORE
    /// `new_state` was read, so that state was thrown away and the caller
    /// recorded nothing. The next reconcile re-planned a CREATE and allocated
    /// a SECOND resource. Measured 2026-08-01: two orphaned EIPs
    /// (3.151.179.36, 18.227.192.150), each billable, neither in state, while
    /// the run reported `created: 0`.
    ///
    /// Carrying the state in the ERROR — rather than returning `Ok` — keeps
    /// the apply correctly failed while making the committed resource
    /// impossible to drop on the floor: a caller must destructure this
    /// variant to handle the error at all.
    #[error("provider returned {} error diagnostic(s) WITH a new_state (partial apply — resource is committed): {}", .diags.len(), fmt_diags(.diags))]
    PartiallyApplied {
        diags: Vec<Diag>,
        state: Box<DynamicValue>,
    },
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),
}

/// Is this provider error worth retrying with backoff? True for transient
/// conditions — chiefly provider-side RATE LIMITING (github/cloud secondary
/// rate limits surface as error diagnostics or transport errors) and
/// transient transport faults. The tfplugin Diagnostic carries no status
/// code, so detection is text-pattern matching on the diagnostic + transport
/// strings. Permanent errors (bad config, schema, auth-denied) return false
/// so they fail fast instead of looping.
#[must_use]
pub fn is_retryable(e: &ProviderError) -> bool {
    const TRANSIENT: &[&str] = &[
        "rate limit",
        "secondary rate",
        "too many request",
        "abuse",
        "quota",
        "try again",
        "retry",
        "429",
        "503",
        "resource_exhausted",
        "unavailable",
        "timeout",
        "timed out",
        "connection reset",
        "broken pipe",
        "tls",
        "transport",
        "h2 protocol",
        "eof",
    ];
    let hit = |s: &str| {
        let l = s.to_ascii_lowercase();
        TRANSIENT.iter().any(|p| l.contains(p))
    };
    match e {
        ProviderError::Transport(s) => hit(s),
        ProviderError::Diagnostics(diags) => {
            diags.iter().any(|d| hit(&d.summary) || hit(&d.detail))
        }
        // NEVER retryable, whatever the diagnostic text says. The resource is
        // already committed provider-side; re-issuing a create without an
        // idempotency key allocates a SECOND one. Retrying a partial apply is
        // strictly worse than failing it.
        ProviderError::PartiallyApplied { .. } => false,
        ProviderError::NoNewState | ProviderError::Schema(_) => false,
    }
}

fn fmt_diags(diags: &[Diag]) -> String {
    diags
        .iter()
        .map(|d| format!("{}: {}", d.summary, d.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A provider: the 8 operations magma performs against one, over
/// `magma_cty` values.
///
/// ── THE WHOLE CONTRACT, AND IT IS SMALL ──────────────────────────────
/// This is every call the apply engine makes. There is no ninth. That
/// matters, because the surface being this small is what makes a native
/// provider tractable at all — the cost of a provider is its API
/// bindings, never its protocol.
///
/// ── `Send + Sync`, AND `Sync` IS NOT DECORATION ─────────────────────
/// A `LiveProvider` is held across `.await` points inside futures that
/// pangea-operator requires to be `Sync`, so a `Box<dyn Provider>` that
/// is merely `Send` fails to compile at the CONSUMER — six E0277s in
/// another repo, pointing at the operator's own functions rather than at
/// this line. The concrete `ProviderConn` this replaced was `Sync`
/// incidentally, so the bound was being satisfied by accident and
/// erasing it to a trait object is what exposed the requirement.
///
/// ── `&mut self`, NOT `&self` ─────────────────────────────────────────
/// Deliberate, and it constrains the shape downstream. The tonic clients
/// behind `ProviderConn` need `&mut` per call, so a `&self` trait would
/// force interior mutability on the ONE implementation that exists
/// today, to buy sharing that no caller wants: each `LiveProvider` owns
/// its connection exclusively. Callers therefore hold `Box<dyn Provider>`
/// (owned), while the FACTORY is what gets shared. A native provider
/// that happens to be stateless can simply ignore the `&mut`.
///
/// ── ORDERING IS A REAL PRECONDITION ──────────────────────────────────
/// `configure` MUST run before any operation other than `get_schema`.
/// The tfplugin protocol requires it, and providers on both SDKv2 and
/// terraform-plugin-framework cache credentials there — some
/// nil-dereference when called unconfigured. The trait cannot express
/// this (it is a sequencing rule, not a type), so a native implementation
/// must state what it does when called out of order rather than assume
/// the engine's ordering holds. `dial_configured_provider` is the one
/// place that establishes it.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// The provider's schema, reduced to implied cty types.
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError>;

    /// Provider credentials / settings. See the ordering note above.
    async fn configure(
        &mut self,
        config: &DynamicValue,
        terraform_version: &str,
    ) -> Result<(), ProviderError>;

    /// The provider's proposed new state PLUS its `requires_replace`
    /// verdict — the only authoritative source for replace-vs-update.
    async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError>;

    /// Execute the change; returns the new state.
    ///
    /// A partial apply — the resource is committed but a follow-up call
    /// failed — is `ProviderError::PartiallyApplied`, carrying the state.
    /// An implementation that loses that state orphans real resources;
    /// see that variant's doc for the measured EIP case.
    async fn apply_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError>;

    /// Refresh. `Ok(None)` means the resource no longer exists, so the
    /// caller drops it from state — distinct from an error.
    async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError>;

    /// Read a data source, so `${data.<type>.<name>.<attr>}` resolves.
    async fn read_data_source(
        &mut self,
        type_name: &str,
        config: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError>;

    /// Adopt an existing resource by id — the import half that powers
    /// import-on-create-conflict and `magma import`.
    async fn import_resource_state(
        &mut self,
        type_name: &str,
        id: &str,
    ) -> Result<Option<DynamicValue>, ProviderError>;

    /// Migrate stored attribute JSON written under an older schema
    /// version up to the current one.
    async fn upgrade_resource_state(
        &mut self,
        type_name: &str,
        stored_version: i64,
        raw_json: &[u8],
    ) -> Result<DynamicValue, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider with no transport at all: no subprocess, no channel, no
    /// Go. It exists to prove the contract is implementable without any of
    /// them — which is the entire premise of this crate, and is otherwise
    /// only an assertion in a doc comment.
    struct TransportlessProvider;

    #[async_trait::async_trait]
    impl Provider for TransportlessProvider {
        async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
            Ok(ProviderSchema {
                provider_config: CtyType::Object(BTreeMap::new()),
                resources: BTreeMap::new(),
                data_sources: BTreeMap::new(),
                resource_versions: BTreeMap::new(),
            })
        }
        async fn configure(&mut self, _: &DynamicValue, _: &str) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn plan_resource_change(
            &mut self,
            _: &str,
            _: &DynamicValue,
            _: &DynamicValue,
            _: &DynamicValue,
        ) -> Result<PlannedChange, ProviderError> {
            Err(ProviderError::NoNewState)
        }
        async fn apply_resource_change(
            &mut self,
            _: &str,
            _: &DynamicValue,
            _: &DynamicValue,
            _: &DynamicValue,
        ) -> Result<DynamicValue, ProviderError> {
            Err(ProviderError::NoNewState)
        }
        async fn read_resource(
            &mut self,
            _: &str,
            _: &DynamicValue,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            Ok(None)
        }
        async fn read_data_source(
            &mut self,
            _: &str,
            _: &DynamicValue,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            Ok(None)
        }
        async fn import_resource_state(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            Ok(None)
        }
        async fn upgrade_resource_state(
            &mut self,
            _: &str,
            _: i64,
            _: &[u8],
        ) -> Result<DynamicValue, ProviderError> {
            Err(ProviderError::NoNewState)
        }
    }

    /// ★ THE `Sync` BOUND IS PINNED HERE, because losing it fails
    /// SOMEWHERE ELSE.
    ///
    /// `LiveProvider` is held across `.await` in futures pangea-operator
    /// requires to be `Sync`. Weaken this bound and this crate still
    /// compiles, magma still compiles, every magma test still passes — and
    /// the operator fails with six E0277s pointing at ITS functions, in
    /// another repository, on a pin bump. Measured exactly that way: the
    /// bound started as `Send` alone and that is how it surfaced.
    #[test]
    fn the_contract_is_send_and_sync() {
        const fn require<T: Send + Sync + ?Sized>() {}
        require::<dyn Provider>();
    }

    /// ★ OBJECT SAFETY IS LOAD-BEARING, so it is pinned rather than assumed.
    ///
    /// The engine will hold `Box<dyn Provider>`, which requires the trait
    /// to stay object-safe. Object safety is easy to lose by accident — one
    /// generic method, one `where Self: Sized`, one `-> impl Trait` — and
    /// the break surfaces at the CALL SITE in another crate, reported as a
    /// confusing "cannot be made into an object" far from the edit that
    /// caused it. Coercing here fails in THIS crate, next to the change.
    #[tokio::test]
    async fn the_contract_is_object_safe_and_transport_free() {
        let mut p: Box<dyn Provider> = Box::new(TransportlessProvider);
        let schema = p.get_schema().await.expect("stub schema");
        assert!(schema.resources.is_empty());
        // `Ok(None)` is "gone", NOT an error — a native implementation that
        // conflates the two would make the engine drop live resources.
        let empty = CtyType::Object(BTreeMap::new());
        let dv = DynamicValue::from_json(&serde_json::json!({}), &empty).expect("empty object");
        assert!(p.read_resource("x", &dv).await.expect("read").is_none());
    }
}
