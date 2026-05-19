//! magma-rubygems — typed in-memory replacement for bundler.
//!
//! Magma owns the Pangea Ruby gem dependency tree end-to-end. This
//! crate parses Gemfile + `*.gemspec` files, resolves the
//! dependency graph in-process (Molinillo-style), fetches gems via
//! typed sources, and materializes a BLAKE3-attested
//! [`VirtualGemTree`] the embedded CRuby evaluator
//! (`pangea-ruby-eval`) consumes.
//!
//! No `bundle install` subprocess; no on-disk `vendor/bundle`
//! cache; one resolution per pangea-operator startup shared across
//! every workspace.
//!
//! Per [`theory/MAGMA-RUBYGEMS.md`](https://github.com/pleme-io/theory/blob/main/MAGMA-RUBYGEMS.md).
//!
//! # Crate status
//!
//! M0 (lockfile parser) not yet started. This file is the typed
//! API skeleton that downstream milestones populate. Every type
//! has a `todo!()` body — the surface is stable, the
//! implementation lands per-milestone.
//!
//! # Milestone-to-module map
//!
//! | Milestone | Modules |
//! |---|---|
//! | M0 — lockfile parser | [`lockfile`] |
//! | M1 — Gemfile + gemspec parsers | [`gemfile_parser`], [`gemspec_parser`], [`manifest`] |
//! | M2 — dependency resolver | [`resolver`] |
//! | M3 — fetcher + cache | [`source`], [`fetcher`], [`cache`] |
//! | M4 — virtual gem tree | [`tree`], [`native`], [`attestation`] |
//! | M5 — pangea-ruby-eval bridge | [`runtime`] |

#![deny(unsafe_code)]
#![allow(dead_code)] // M0 stub — fields will be wired per milestone.

pub mod attestation;
pub mod cache;
pub mod fetcher;
pub mod gemfile_parser;
pub mod gemspec_parser;
pub mod lockfile;
pub mod manifest;
pub mod native;
pub mod nix;
pub mod nixhash;
pub mod resolver;
pub mod runtime;
pub mod source;
pub mod tree;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Top-level error surface ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum RubygemsError {
    #[error("gemfile parse: {0}")]
    GemfileParse(String),
    #[error("gemspec parse: {0}")]
    GemspecParse(String),
    #[error("lockfile parse: {0}")]
    LockfileParse(String),
    #[error("resolver: {0}")]
    Resolver(String),
    #[error("fetch: {0}")]
    Fetch(String),
    #[error("native build: {0}")]
    NativeBuild(String),
    #[error("materialize: {0}")]
    Materialize(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias used across magma-rubygems.
pub type Result<T> = std::result::Result<T, RubygemsError>;

// ── Re-exports for the canonical API surface ──────────────────────

pub use manifest::{Dependency, Manifest, RubyVersion};
pub use lockfile::{Lockfile, ResolvedGem};
pub use source::Source;
pub use tree::VirtualGemTree;

// ── Toplevel async orchestration (M2+M3+M4 composed) ──────────────

/// Resolve a Manifest into a Lockfile (M2 destination). The
/// resolver runs the typed dependency-graph solver; the lockfile
/// is the deterministic resolution artifact.
pub async fn resolve(manifest: &Manifest) -> Result<Lockfile> {
    resolver::resolve(manifest).await
}

/// Materialize a Lockfile into a `VirtualGemTree` (M3+M4
/// destination). Fetches every gem, extracts to a typed tree,
/// computes the BLAKE3 closure attestation.
pub async fn materialize(lock: &Lockfile) -> Result<VirtualGemTree> {
    tree::materialize(lock).await
}

/// One-shot pipeline: parse manifest source → resolve → materialize.
/// Useful for the operator-side startup path where the gem tree is
/// computed once for the whole fleet.
pub async fn realize(gemfile_source: &str) -> Result<VirtualGemTree> {
    let manifest = gemfile_parser::parse(gemfile_source)?;
    let lock = resolve(&manifest).await?;
    materialize(&lock).await
}

// ── Canonical exposed types (frontmatter for future milestones) ──

/// One resolved gem in the closure. Future milestones populate
/// fields as they land.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    pub name:    String,
    pub version: String,
    pub source:  Source,
    /// BLAKE3 over the canonical `gemspec` text. Identity for the
    /// resolved gem; two specs with the same hash are bit-identical.
    pub gemspec_hash: String,
}

/// Snapshot of "what magma-rubygems knows about the materialized
/// closure right now." Returned by `runtime::status` once that
/// module lands; for now just a typed placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub resolved_gems:   usize,
    pub materialized:    bool,
    pub attestation:     Option<String>,
}
