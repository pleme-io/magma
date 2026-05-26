//! `VirtualGemTree` — typed materialized gem closure (M4 destination).
//!
//! Once resolved + fetched, every gem is extracted into a typed
//! tree rooted in a tmpfs (or pure-RAM via FUSE) directory. The
//! tree carries:
//!
//! * A BLAKE3 attestation over the canonical projection
//!   `[(name, version, source, gemspec_hash)]`.
//! * The `GEM_PATH` the CRuby interpreter should set.
//! * A handle that keeps the tmpfs alive for as long as the
//!   handle is held.
//!
//! Operator-side usage: build ONE tree at startup, share it across
//! every workspace's reconcile (pangea-ruby-eval picks up
//! `GEM_PATH` from this handle).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Result, lockfile::Lockfile};

/// Opaque BLAKE3-attested materialized gem closure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualGemTree {
    /// Filesystem root the CRuby interpreter sees. M4 backs this
    /// with a tmpfs-mounted tempdir kept alive by the handle.
    pub gem_path: PathBuf,
    /// BLAKE3 attestation over the canonical closure projection.
    pub attestation: String,
    /// Resolved gem count (informational; bundle_id is the load-
    /// bearing identity).
    pub gem_count: usize,
}

/// Materialize a `Lockfile` into a `VirtualGemTree`.
///
/// M4 implementation TBD. Composes M3 fetcher + M4 native build.
pub async fn materialize(_lock: &Lockfile) -> Result<VirtualGemTree> {
    Err(crate::RubygemsError::Materialize(
        "M4 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
