//! magma-provider-registry — the typed [`ProviderRegistry`] resolution
//! plane for the Magma Dynamic Provider Plane.
//!
//! Spec: `theory/MAGMA-PROVIDER-PLANE.md`. This crate is the **first
//! increment**: a typed registry trait + two concrete resolvers (a
//! directory mirror and an optional Postgres registry) + a fallback
//! chain. It does **not** yet wire into `magma-apply`'s `ApplyContext`,
//! download providers, or perform live updates — those are the next
//! increment (§V). The crate is additive: nothing in the apply engine
//! depends on it yet.
//!
//! # The destination (§I)
//!
//! Provider availability is a DB-resolved, live-updatable property — not
//! a build-time constant. At apply time magma resolves the workspace's
//! `required_providers` against this plane:
//!
//! 1. **DB registry** (the durable source of truth) — Postgres, keyed by
//!    `(source, version, os, arch)`, content-addressed + hash-verified.
//! 2. **`MAGMA_PROVIDER_DIR`** — the Nix-baked seed / offline fallback.
//!
//! [`ChainRegistry`] composes the two: DB first, dir on a miss. The
//! `FetchProvider` remediation (download-on-miss) is the next increment.
//!
//! # The one honest filesystem reach (§III)
//!
//! go-plugin `exec`s the provider binary from a *path*. A directory
//! registry resolves a path directly; a DB registry materializes its
//! blob to a transient exec cache and hash-verifies it. The binary's
//! durable home is Postgres (in the DB case), never pod disk — the path
//! is a materialized cache, not storage.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod mirror;

mod dir;
pub use dir::DirRegistry;

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PgRegistry;

#[cfg(test)]
mod tests;

/// Typed description of a provider in the registry — its coordinate
/// (`source`, `version`, `os`, `arch`) plus the BLAKE3 `content_hash`
/// of its binary. Every field is a `String` (the wire shape the DB
/// stores + the resolver keys on); content-addressing is by
/// `content_hash`.
///
/// Two `ProviderInfo`s describe "the same provider build" iff they
/// agree on all five fields. The hash is what a [`ProviderRegistry`]
/// verifies on read before trusting a materialized binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Registry source, e.g. `"cloudflare/cloudflare"`,
    /// `"hashicorp/random"`, `"marcfrederick/porkbun"`.
    pub source: String,
    /// Resolved provider version, e.g. `"5.12.0"`.
    pub version: String,
    /// Target OS, e.g. `"linux"`, `"darwin"`.
    pub os: String,
    /// Target architecture, e.g. `"amd64"`, `"arm64"`.
    pub arch: String,
    /// BLAKE3 of the provider binary, lowercase hex. Verified on read.
    pub content_hash: String,
}

impl ProviderInfo {
    /// Construct a [`ProviderInfo`] from owned/borrowed string parts.
    pub fn new(
        source: impl Into<String>,
        version: impl Into<String>,
        os: impl Into<String>,
        arch: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            version: version.into(),
            os: os.into(),
            arch: arch.into(),
            content_hash: content_hash.into(),
        }
    }

    /// The bare provider name (the last `/`-separated segment of
    /// `source`). `"cloudflare/cloudflare"` → `"cloudflare"`;
    /// `"random"` → `"random"`. This is what the on-disk
    /// `terraform-provider-<name>` binary is named after, so the
    /// directory resolver keys off it.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        self.source.rsplit('/').next().unwrap_or(&self.source)
    }
}

/// A resolved provider — the on-disk path go-plugin will `exec`, plus
/// the [`ProviderInfo`] that produced it (when the registry knows it).
///
/// `info` is `Some` for registries that carry typed metadata (DB);
/// `None` for the directory mirror, which resolves a path by name
/// without recording a hash. The path is always present — it is the
/// load-bearing output (`magma_plugin::Plugin::spawn` consumes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHandle {
    /// The on-disk path to the provider binary.
    pub path: PathBuf,
    /// Typed metadata, when the resolving registry carries it.
    pub info: Option<ProviderInfo>,
}

impl ProviderHandle {
    /// A handle that carries only a path (the directory-mirror case).
    #[must_use]
    pub fn from_path(path: PathBuf) -> Self {
        Self { path, info: None }
    }

    /// A handle that carries both the path and its typed metadata
    /// (the DB-registry case).
    #[must_use]
    pub fn with_info(path: PathBuf, info: ProviderInfo) -> Self {
        Self {
            path,
            info: Some(info),
        }
    }
}

/// Typed errors a [`ProviderRegistry`] can return. A *miss* (the
/// provider is not in this registry) is **not** an error — it is
/// `Ok(None)`, so a [`ChainRegistry`] can fall through. Errors are
/// reserved for genuine failures: I/O, a backend fault, or a
/// content-hash mismatch (a tampered/corrupt binary).
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The binary materialized for `provider@version` hashed to
    /// `actual`, but the registry recorded `expected`. The binary is
    /// rejected — never loaded — so a corrupt or tampered row is a
    /// typed error, not a silently-spawned plugin. (`provider`, not
    /// `source`: a field named `source` would be treated by `thiserror`
    /// as the error's `std::error::Error` cause.)
    #[error(
        "content-hash mismatch for {provider}@{version} ({os}_{arch}): \
         expected {expected}, computed {actual}"
    )]
    ContentHashMismatch {
        provider: String,
        version: String,
        os: String,
        arch: String,
        expected: String,
        actual: String,
    },

    /// A filesystem error while resolving/materializing a binary.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A backend (DB) error. Carried as a string so the trait surface
    /// stays driver-agnostic (the `postgres` feature maps `sqlx::Error`
    /// into this).
    #[error("registry backend: {0}")]
    Backend(String),
}

/// The typed provider-resolution surface. An implementation answers
/// "do you have the provider binary for `(source, version, os, arch)`,
/// and if so, where is it on disk?"
///
/// - `Ok(Some(handle))` — resolved; `handle.path` is exec-ready.
/// - `Ok(None)` — a clean miss; the caller may try another registry.
/// - `Err(_)` — a genuine failure (I/O, backend, hash mismatch).
///
/// The miss-is-`None` contract is what makes [`ChainRegistry`]
/// fallback composable.
#[async_trait::async_trait]
pub trait ProviderRegistry: Send + Sync {
    /// Resolve the provider binary for the given coordinate.
    async fn resolve(
        &self,
        source: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> Result<Option<ProviderHandle>, RegistryError>;
}

/// A two-tier resolver: try `primary`, and on a clean miss
/// (`Ok(None)`) fall through to `fallback`. Per §IV the canonical
/// composition is DB-then-dir: `ChainRegistry::new(pg, dir)`.
///
/// A genuine error from `primary` (I/O, backend, hash mismatch) is
/// **not** swallowed — it propagates, because a hash mismatch is a
/// correctness failure, not a "try the next registry" miss. Only a
/// clean `None` triggers the fallback.
pub struct ChainRegistry<P, F> {
    primary: P,
    fallback: F,
}

impl<P, F> ChainRegistry<P, F> {
    /// Compose `primary` (tried first) with `fallback` (on a clean miss).
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait::async_trait]
impl<P, F> ProviderRegistry for ChainRegistry<P, F>
where
    P: ProviderRegistry,
    F: ProviderRegistry,
{
    async fn resolve(
        &self,
        source: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> Result<Option<ProviderHandle>, RegistryError> {
        match self.primary.resolve(source, version, os, arch).await? {
            Some(handle) => Ok(Some(handle)),
            None => self.fallback.resolve(source, version, os, arch).await,
        }
    }
}

/// Compute the lowercase-hex BLAKE3 of `bytes` — the canonical
/// content-hash across pleme-io's tameshi attestation chain. Used by
/// DB registries to verify a materialized binary against the recorded
/// `content_hash` before trusting it.
#[must_use]
pub fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

/// What a seed run did. The DENOMINATOR travels with the result.
///
/// `scanned` is here because "inserted 0" has two very different causes —
/// the registry was already complete, or the mirror was empty and nothing
/// was ever going to be inserted. A caller that only sees `inserted`
/// cannot tell a healthy no-op from a broken deployment, which is the same
/// shape as an empty resolve rendering a successful plan of nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedReport {
    /// Provider binaries found in the mirror.
    pub scanned: usize,
    /// Rows newly written.
    pub inserted: usize,
    /// Rows already present at the same coordinate — re-seeding is free.
    pub already_present: usize,
}

impl SeedReport {
    /// Did the mirror contain anything at all?
    ///
    /// Deliberately not an error inside the seeder: a magma with no bake is
    /// a legitimate configuration once the DB is the source of truth. It is
    /// a question the CALLER has to answer, so it is exposed as one.
    #[must_use]
    pub const fn mirror_was_empty(&self) -> bool {
        self.scanned == 0
    }
}
