//! Dependency resolver — pure-Rust Molinillo-style backtracking
//! solver (M2 destination).
//!
//! Given a `Manifest`, produces a `Lockfile` solving the
//! dependency graph: version constraints, platform pinning,
//! transitive deps, conflict resolution.
//!
//! Property test gate: `resolve(parse(real_gemfile))` matches
//! bundler-produced lockfile byte-for-byte across all Pangea
//! workspaces.

use crate::{lockfile::Lockfile, manifest::Manifest, Result, RubygemsError};

/// Resolve a Manifest into a Lockfile.
///
/// M2 implementation TBD.
pub async fn resolve(_manifest: &Manifest) -> Result<Lockfile> {
    Err(RubygemsError::Resolver(
        "M2 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
