//! magma-operator-backend — bridge between K8s-operator state
//! stores and magma's `Backend` trait.
//!
//! pangea-operator (and any future pleme-io operator) already owns
//! a state-storage abstraction — typically backed by PostgreSQL,
//! configmaps, or an in-memory mock for tests. magma owns a typed
//! `Backend` trait shaped around plan/apply round-trips. This
//! crate is the canonical adapter between them.
//!
//! # Two pieces
//!
//! 1. **`AsyncStateStore` trait** — what an operator implements (one
//!    method-pair: `load_state_bytes` / `save_state_bytes` over a
//!    typed key triple). Object-safe; the operator threads
//!    `Arc<dyn AsyncStateStore>` into magma.
//!
//! 2. **`OperatorBackend<S>` adapter** — implements
//!    `magma_backend::Backend` over an `AsyncStateStore`. Handles
//!    the tofu-state ⇄ magma-state conversion. Constructed once per
//!    reconcile from the operator's wider key (schema + template +
//!    state name).
//!
//! # State shape conversion
//!
//! Tofu serializes resources with string-encoded provider
//! references (`provider["registry.opentofu.org/hashicorp/aws"]`)
//! and an opaque resources array. magma's typed `State` uses a
//! `ProviderReference { source, name, alias }` struct + typed
//! `StateResource` instances. The `tofu_state` module here is a thin
//! wrapper over the canonical, real-fixture-tested converter in
//! `magma_state::tfstate_v4` (also what `magma_state::read_state` /
//! `write_state` and `magma_backend::LocalBackend` use directly) — a
//! malformed resource fails the whole decode with a typed error
//! rather than being silently dropped.
//!
//! # Locking
//!
//! Operators typically own locking at a higher level (PG advisory
//! locks, K8s leader election). magma's `Backend::lock` /
//! `unlock` calls are wired to `AsyncStateStore::lock` /
//! `unlock` so the operator can plug its own lock semantics in.
//! Default impls treat lock/unlock as no-ops (synthetic ids); real
//! operators should override.
//!
//! Per `theory/MAGMA-OPERATOR-BACKEND.md`.

use std::sync::Arc;

use async_trait::async_trait;
use magma_backend::{Backend, BackendError, LockId};
use magma_types::State;
use thiserror::Error;

pub use tofu_state::{TofuStateError, magma_to_tofu, tofu_to_magma};

// ── Errors ────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store: {0}")]
    Inner(String),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("tofu-state conversion: {0}")]
    TofuState(#[from] TofuStateError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<StoreError> for BackendError {
    fn from(e: StoreError) -> Self {
        BackendError::NotImplemented(e.to_string())
    }
}

// ── AsyncStateStore — the trait operators implement ───────────────

/// What an operator's state-storage layer needs to expose for
/// magma's `Backend` to talk to it. Three methods (the lock/unlock
/// pair is collapsed into the trait — most implementations are
/// no-ops since the operator owns higher-level locking).
///
/// Object-safe. `Arc<dyn AsyncStateStore>` is the canonical
/// handle the operator threads into magma.
#[async_trait]
pub trait AsyncStateStore: Send + Sync {
    /// Load raw state bytes for the configured key. Returns `Ok(None)`
    /// if no state has been persisted yet (treated as a fresh
    /// workspace by magma).
    async fn load_state_bytes(&self) -> Result<Option<Vec<u8>>, StoreError>;

    /// Persist raw state bytes. Implementations should be
    /// idempotent (upsert semantics).
    async fn save_state_bytes(&self, bytes: &[u8]) -> Result<(), StoreError>;

    /// Acquire a lock. Default no-op; operators override when they
    /// want magma-level locking (rare — the operator's own
    /// reconciler typically owns locking).
    async fn lock(&self) -> Result<LockId, StoreError> {
        Ok(LockId::new())
    }

    /// Release a lock. Default no-op.
    async fn unlock(&self, _lock_id: &LockId) -> Result<(), StoreError> {
        Ok(())
    }
}

// ── OperatorBackend adapter ───────────────────────────────────────

/// Adapts an `AsyncStateStore` into `magma_backend::Backend`. The
/// generic parameter is the store impl; `Arc` is the conventional
/// handle shape (so the backend is cheap to clone per-reconcile).
///
/// Choose between the magma-shape on-disk encoding (default — for
/// magma-only state stores) and the tofu-shape encoding (for
/// cross-executor compatibility) via `BackendShape`.
pub struct OperatorBackend<S: AsyncStateStore + ?Sized> {
    inner: Arc<S>,
    shape: BackendShape,
}

/// On-disk encoding choice. `Magma` is the typed serde-derived
/// format magma uses internally (byte-equal round-trip through
/// magma; not readable by tofu). `Tofu` is the OpenTofu serialized
/// format (readable by both; M0.11 ships the byte-equal converter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendShape {
    /// Default for new state stores that magma owns end-to-end.
    Magma,
    /// Use when the same state file is read by both magma + tofu
    /// (mixed-executor fleets). Round-trips through `tofu_state`.
    Tofu,
}

impl<S: AsyncStateStore + ?Sized> OperatorBackend<S> {
    /// Build a backend with the default magma-shape encoding.
    pub fn new(inner: Arc<S>) -> Self {
        Self {
            inner,
            shape: BackendShape::Magma,
        }
    }

    /// Build a backend with a chosen on-disk encoding shape.
    pub fn with_shape(inner: Arc<S>, shape: BackendShape) -> Self {
        Self { inner, shape }
    }
}

#[async_trait]
impl<S: AsyncStateStore + ?Sized> Backend for OperatorBackend<S> {
    async fn read_state(&self) -> Result<State, BackendError> {
        let bytes = self
            .inner
            .load_state_bytes()
            .await
            .map_err(BackendError::from)?;
        match bytes {
            None => Ok(magma_state::empty_state()),
            Some(b) => match self.shape {
                BackendShape::Magma => decode_magma_shape(&b),
                BackendShape::Tofu => decode_tofu_shape(&b),
            },
        }
    }

    async fn write_state(&self, state: &State) -> Result<(), BackendError> {
        let bytes = match self.shape {
            BackendShape::Magma => serde_json::to_vec_pretty(state)
                .map_err(|e| backend_other(format!("encode magma: {e}")))?,
            BackendShape::Tofu => {
                magma_to_tofu(state).map_err(|e| backend_other(format!("encode tofu: {e}")))?
            }
        };
        self.inner
            .save_state_bytes(&bytes)
            .await
            .map_err(BackendError::from)?;
        Ok(())
    }

    async fn lock(&self) -> Result<LockId, BackendError> {
        self.inner.lock().await.map_err(BackendError::from)
    }

    async fn unlock(&self, lock_id: &LockId) -> Result<(), BackendError> {
        self.inner.unlock(lock_id).await.map_err(BackendError::from)
    }
}

fn decode_magma_shape(bytes: &[u8]) -> Result<State, BackendError> {
    serde_json::from_slice(bytes).map_err(|e| backend_other(format!("decode magma state: {e}")))
}

fn decode_tofu_shape(bytes: &[u8]) -> Result<State, BackendError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| backend_other(format!("decode tofu state: {e}")))?;
    tofu_to_magma(&raw).map_err(|e| backend_other(format!("convert tofu state: {e}")))
}

// magma-backend's `BackendError` doesn't yet expose a generic
// `Other` variant; we route adapter-level failures through
// `NotImplemented` for M0.10. A follow-up extends `BackendError`
// with a dedicated `Other(String)` variant and we switch over.
fn backend_other(msg: impl Into<String>) -> BackendError {
    BackendError::NotImplemented(msg.into())
}

// ── Tofu state conversion ─────────────────────────────────────────

pub mod tofu_state {
    //! Convert between OpenTofu's serialized state format and
    //! magma's typed `State`.
    //!
    //! A thin, `serde_json::Value`-shaped wrapper around
    //! `magma_state::tfstate_v4` — the canonical, real-fixture-tested
    //! wire-format converter (see that module's doc for the exact
    //! schema, what's byte-exact-verified, and named gaps). This
    //! module used to carry its own, independent, unverified
    //! implementation; per the "solve once" rule it now delegates
    //! rather than re-diverging. Two behavioral corrections versus the
    //! prior implementation, both load-bearing:
    //!
    //!   1. **No permissive resource-skipping.** The prior
    //!      `tofu_to_magma` silently dropped any resource entry it
    //!      couldn't parse (`filter_map`, no warning ever actually
    //!      emitted despite the doc comment claiming one). A silently
    //!      truncated state is a silent-corruption bug — this version
    //!      fails loudly with a typed error instead.
    //!   2. **No hardcoded registry host.** The prior
    //!      `format_provider_reference` always wrote back
    //!      `registry.terraform.io/...` regardless of what was parsed,
    //!      which corrupts (doubles) an OpenTofu-native
    //!      `registry.opentofu.org` reference on round-trip — see
    //!      `magma_state::tfstate_v4`'s module doc for the empirical
    //!      fixture that caught this.

    use magma_state::StateError;
    use magma_types::State;
    use serde_json::Value;
    pub use magma_state::tfstate_v4::{format_provider_reference, parse_provider_reference};

    #[derive(Debug, thiserror::Error)]
    pub enum TofuStateError {
        #[error("expected top-level object")]
        NotAnObject,
        #[error("state wire format: {0}")]
        Wire(#[from] StateError),
        #[error("encode: {0}")]
        Encode(#[from] serde_json::Error),
    }

    /// Tofu serialized JSON → magma's typed State.
    pub fn tofu_to_magma(v: &Value) -> Result<State, TofuStateError> {
        if !v.is_object() {
            return Err(TofuStateError::NotAnObject);
        }
        let bytes = serde_json::to_vec(v)?;
        Ok(magma_state::tfstate_v4::decode(&bytes)?)
    }

    /// magma's typed State → tofu serialized JSON bytes.
    pub fn magma_to_tofu(state: &State) -> Result<Vec<u8>, TofuStateError> {
        Ok(magma_state::tfstate_v4::encode(state)?)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Mutex;

    // ── Test AsyncStateStore impl backed by a single Vec<u8> ─────

    #[derive(Default)]
    struct MemStore(Mutex<Option<Vec<u8>>>);

    #[async_trait]
    impl AsyncStateStore for MemStore {
        async fn load_state_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn save_state_bytes(&self, bytes: &[u8]) -> Result<(), StoreError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
    }

    fn fixture_state() -> State {
        magma_fixtures::StateBuilder::new()
            .lineage(uuid::Uuid::nil())
            .serial(7)
            .resource(
                "aws_iam_role",
                "alpha",
                serde_json::json!({"name": "alpha"}),
            )
            .build()
    }

    // ── OperatorBackend round-trips ──────────────────────────────

    #[tokio::test]
    async fn empty_store_yields_fresh_state() {
        let store: Arc<MemStore> = Arc::new(MemStore::default());
        let backend = OperatorBackend::new(Arc::clone(&store));
        let state = backend.read_state().await.unwrap();
        assert_eq!(state.resources.len(), 0);
        assert_eq!(state.version, 4);
    }

    #[tokio::test]
    async fn magma_shape_round_trip_through_store() {
        let store: Arc<MemStore> = Arc::new(MemStore::default());
        let backend = OperatorBackend::new(Arc::clone(&store));
        let want = fixture_state();
        backend.write_state(&want).await.unwrap();
        let got = backend.read_state().await.unwrap();
        assert_eq!(got.serial, want.serial);
        assert_eq!(got.lineage, want.lineage);
        assert_eq!(got.resources.len(), want.resources.len());
        assert_eq!(got.resources[0].address.name, "alpha");
    }

    #[tokio::test]
    async fn tofu_shape_round_trip_through_store() {
        let store: Arc<MemStore> = Arc::new(MemStore::default());
        let backend = OperatorBackend::with_shape(Arc::clone(&store), BackendShape::Tofu);
        let want = fixture_state();
        backend.write_state(&want).await.unwrap();
        // What landed in the store should be valid tofu JSON.
        let bytes = store.0.lock().unwrap().clone().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["version"], 4);
        let provider_str = parsed["resources"][0]["provider"].as_str().unwrap();
        assert!(
            // A short-form source ("hashicorp/aws", what magma-config
            // and StateBuilder build) is qualified with OpenTofu's own
            // default registry host on write — not Terraform CLI's.
            // See magma_state::tfstate_v4's module doc for the
            // empirical fixture that pins this down.
            provider_str.contains("registry.opentofu.org/hashicorp/aws"),
            "tofu shape should serialize provider in canonical form, got: {provider_str}",
        );
        // Reading back through the same backend recovers the typed state.
        let got = backend.read_state().await.unwrap();
        assert_eq!(got.resources.len(), want.resources.len());
        assert_eq!(
            got.resources[0].provider.source,
            "registry.opentofu.org/hashicorp/aws",
        );
    }

    // ── tofu_state conversions ───────────────────────────────────

    #[test]
    fn parse_provider_reference_preserves_registry_host_verbatim() {
        // The registry host is carried through unchanged — NOT
        // normalized to either vendor's default. This is the fix for
        // the corruption bug: a prior implementation stripped
        // "registry.terraform.io/" specifically, so any OTHER host
        // (including OpenTofu's own default) round-tripped wrong.
        let r = tofu_state::parse_provider_reference(
            "provider[\"registry.terraform.io/hashicorp/aws\"]",
        )
        .unwrap();
        assert_eq!(r.source, "registry.terraform.io/hashicorp/aws");
        assert_eq!(r.name, "aws");

        let r2 = tofu_state::parse_provider_reference(
            "provider[\"registry.opentofu.org/hashicorp/aws\"]",
        )
        .unwrap();
        assert_eq!(r2.source, "registry.opentofu.org/hashicorp/aws");
    }

    #[test]
    fn format_provider_reference_round_trips() {
        let original = "provider[\"registry.terraform.io/hashicorp/aws\"]";
        let parsed = tofu_state::parse_provider_reference(original).unwrap();
        let formatted = tofu_state::format_provider_reference(&parsed);
        assert_eq!(original, formatted);
    }

    #[test]
    fn tofu_to_magma_extracts_managed_resources() {
        let value = serde_json::json!({
            "version": 4,
            "terraform_version": "1.7.0",
            "serial": 3,
            "lineage": "00000000-0000-0000-0000-000000000000",
            "outputs": {},
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_vpc",
                    "name": "net",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [{
                        "schema_version": 0,
                        "attributes":     { "cidr_block": "10.0.0.0/16" },
                        "sensitive_attributes": []
                    }]
                }
            ]
        });
        let state = tofu_state::tofu_to_magma(&value).unwrap();
        assert_eq!(state.resources.len(), 1);
        let r = &state.resources[0];
        assert_eq!(r.address.type_id.0, "aws_vpc");
        assert_eq!(r.provider.source, "registry.terraform.io/hashicorp/aws");
        assert_eq!(r.instances[0].schema_version, 0);
    }

    #[test]
    fn tofu_to_magma_fails_loudly_on_an_unparseable_resource() {
        // The prior implementation silently DROPPED a resource entry
        // it couldn't parse (`filter_map`) — a real-fixture read that
        // hits one malformed entry would silently lose data instead of
        // surfacing the problem. This is the corrected behavior: a
        // malformed resource fails the whole decode with a typed
        // error, never a silent truncation.
        let value = serde_json::json!({
            "version": 4,
            "terraform_version": "1.7.0",
            "serial": 1,
            "lineage": "00000000-0000-0000-0000-000000000000",
            "outputs": {},
            "resources": [
                { "garbage": true },
                {
                    "mode": "managed",
                    "type": "aws_iam_role",
                    "name": "ok",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": []
                }
            ]
        });
        let err = tofu_state::tofu_to_magma(&value).unwrap_err();
        assert!(matches!(err, tofu_state::TofuStateError::Wire(_)));
    }

    #[test]
    fn magma_to_tofu_emits_canonical_provider_form() {
        let state = fixture_state();
        let bytes = tofu_state::magma_to_tofu(&state).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // The provider field is JSON-encoded so embedded quotes are
        // backslash-escaped. Look for the unescaped infix instead.
        assert!(
            s.contains("registry.opentofu.org/hashicorp/aws"),
            "missing canonical provider source in:\n{s}"
        );
        // Compact JSON (no pretty-printing) — matches what OpenTofu
        // itself writes to disk, per the empirical fixture in
        // magma_state::tfstate_v4's test corpus.
        assert!(s.contains("\"mode\":\"managed\""));
        assert!(s.contains("\"type\":\"aws_iam_role\""));
        // Round-trip via parsed JSON: the typed provider string ends
        // back in `provider["registry.opentofu.org/hashicorp/aws"]` form.
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            parsed["resources"][0]["provider"].as_str().unwrap(),
            "provider[\"registry.opentofu.org/hashicorp/aws\"]",
        );
    }

    // ── proptest: tofu round-trip ────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn tofu_round_trip_preserves_resource_count(
            count in 0usize..6,
        ) {
            let mut builder = magma_fixtures::StateBuilder::new()
                .lineage(uuid::Uuid::nil())
                .serial(1);
            for i in 0..count {
                builder = builder.resource(
                    "aws_iam_role",
                    &format!("r{i}"),
                    serde_json::json!({ "name": format!("r{i}") }),
                );
            }
            let original = builder.build();

            let tofu_bytes = tofu_state::magma_to_tofu(&original).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&tofu_bytes).unwrap();
            let recovered = tofu_state::tofu_to_magma(&value).unwrap();

            prop_assert_eq!(recovered.resources.len(), original.resources.len());
            prop_assert_eq!(recovered.serial, original.serial);
            prop_assert_eq!(recovered.lineage, original.lineage);
        }

        #[test]
        fn tofu_round_trip_preserves_resource_names(
            names in proptest::collection::vec("[a-z][a-z0-9_]{0,8}", 0..=5),
        ) {
            // Dedup so the same name doesn't appear twice in a tf state.
            let unique: std::collections::HashSet<String> = names.into_iter().collect();
            let mut builder = magma_fixtures::StateBuilder::new()
                .lineage(uuid::Uuid::nil())
                .serial(1);
            for n in &unique {
                builder = builder.resource(
                    "aws_iam_role",
                    n,
                    serde_json::json!({"name": n}),
                );
            }
            let original = builder.build();
            let bytes = tofu_state::magma_to_tofu(&original).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let recovered = tofu_state::tofu_to_magma(&value).unwrap();

            let want: std::collections::HashSet<String> = unique;
            let got: std::collections::HashSet<String> = recovered
                .resources.iter().map(|r| r.address.name.clone()).collect();
            prop_assert_eq!(got, want);
        }

        /// Arbitrary serial values survive the magma↔tofu round-trip
        /// — a regression test for any future serial-encoding change.
        #[test]
        fn tofu_round_trip_preserves_serial(
            serial in 0u64..=u64::MAX,
        ) {
            let original = magma_fixtures::StateBuilder::new()
                .lineage(uuid::Uuid::nil())
                .serial(serial)
                .build();
            let bytes = tofu_state::magma_to_tofu(&original).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let recovered = tofu_state::tofu_to_magma(&value).unwrap();
            prop_assert_eq!(recovered.serial, serial);
        }

        /// Arbitrary lineage UUIDs survive the round-trip without
        /// loss. Lineage drift between magma and tofu would silently
        /// corrupt state attribution; this property forbids it.
        #[test]
        fn tofu_round_trip_preserves_lineage(
            bytes in proptest::array::uniform16(0u8..=255),
        ) {
            let lineage = uuid::Uuid::from_bytes(bytes);
            let original = magma_fixtures::StateBuilder::new()
                .lineage(lineage)
                .serial(1)
                .build();
            let serialized = tofu_state::magma_to_tofu(&original).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
            let recovered = tofu_state::tofu_to_magma(&value).unwrap();
            prop_assert_eq!(recovered.lineage, lineage);
        }

        /// Resource attributes survive the round-trip — magma never
        /// mangles user-provided JSON.
        #[test]
        fn tofu_round_trip_preserves_attributes(
            name in "[a-z][a-z0-9]{0,8}",
            arn  in "arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9_-]{1,16}",
        ) {
            let attrs = serde_json::json!({
                "name": name,
                "arn":  arn,
                "tags": {"managed_by": "magma"},
            });
            let original = magma_fixtures::StateBuilder::new()
                .lineage(uuid::Uuid::nil())
                .resource("aws_iam_role", &name, attrs.clone())
                .build();
            let bytes = tofu_state::magma_to_tofu(&original).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let recovered = tofu_state::tofu_to_magma(&value).unwrap();
            prop_assert_eq!(recovered.resources.len(), 1);
            prop_assert_eq!(&recovered.resources[0].instances[0].attributes, &attrs);
        }

        /// magma_shape and tofu_shape don't trample each other when
        /// written into separate stores. Both backends start empty,
        /// write the same logical state through their respective
        /// shapes, read back — both round-trip cleanly.
        #[test]
        fn magma_and_tofu_shapes_are_isolated(
            serial in 0u64..1000,
        ) {
            let want = magma_fixtures::StateBuilder::new()
                .lineage(uuid::Uuid::nil())
                .serial(serial)
                .resource("aws_iam_role", "x", serde_json::json!({"name": "x"}))
                .build();

            let store_magma: Arc<MemStore> = Arc::new(MemStore::default());
            let store_tofu:  Arc<MemStore> = Arc::new(MemStore::default());
            let bm = OperatorBackend::new(Arc::clone(&store_magma));
            let bt = OperatorBackend::with_shape(Arc::clone(&store_tofu), BackendShape::Tofu);

            let rt_async = tokio::runtime::Runtime::new().unwrap();
            rt_async.block_on(async {
                bm.write_state(&want).await.unwrap();
                bt.write_state(&want).await.unwrap();
                let got_m = bm.read_state().await.unwrap();
                let got_t = bt.read_state().await.unwrap();
                prop_assert_eq!(got_m.serial,           want.serial);
                prop_assert_eq!(got_m.resources.len(),  want.resources.len());
                prop_assert_eq!(got_t.serial,           want.serial);
                prop_assert_eq!(got_t.resources.len(),  want.resources.len());
                // Bytes in store_tofu must look like canonical tofu
                // JSON (parseable as object with `version`/`resources`).
                let tofu_bytes = store_tofu.0.lock().unwrap().clone().unwrap();
                let parsed: serde_json::Value =
                    serde_json::from_slice(&tofu_bytes).unwrap();
                prop_assert!(parsed.is_object());
                prop_assert!(parsed.get("resources").is_some());
                Ok(())
            }).unwrap();
        }
    }

    // ── Cross-shape regression: tofu-shape bytes are NOT magma-shape ─

    /// Tofu-shaped state bytes are not interchangeable with magma-
    /// shaped state bytes — magma's typed serde format and tofu's
    /// resource-array format have incompatible top-level keys. This
    /// test locks that boundary in: a Tofu-shape store cannot be
    /// silently misread by a Magma-shape backend.
    #[tokio::test]
    async fn shape_mismatch_fails_loudly() {
        let store: Arc<MemStore> = Arc::new(MemStore::default());

        // Write Tofu-shaped state.
        let bt = OperatorBackend::with_shape(Arc::clone(&store), BackendShape::Tofu);
        bt.write_state(&fixture_state()).await.unwrap();

        // Read with the Magma-shape backend; expect an error
        // because magma's typed format requires fields that aren't
        // present in the tofu shape.
        let bm = OperatorBackend::new(Arc::clone(&store));
        let result = bm.read_state().await;
        assert!(
            result.is_err(),
            "magma backend silently accepted tofu-shaped bytes — \
             cross-shape misread would silently corrupt state",
        );
    }
}
