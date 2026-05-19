//! Gemfile.lock parser + emitter (M0 destination — first to land).
//!
//! Reads bundler's lockfile format, produces typed `Lockfile`,
//! round-trips byte-identical on emit. M0 acceptance gate: every
//! `pangea-architectures/workspaces/*/Gemfile.lock` parses + emits
//! bit-for-bit.

use serde::{Deserialize, Serialize};

use crate::{Result, RubygemsError, Spec};

/// Typed Gemfile.lock content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    /// Bundler version that produced this lockfile (preserved for
    /// round-trip compat, NOT load-bearing — magma's own resolver
    /// can regenerate from manifest).
    pub bundler_version: Option<String>,
    /// Pinned Ruby version (mirrors manifest::RubyVersion).
    pub ruby: Option<crate::manifest::RubyVersion>,
    /// Resolved gems: name + version + source.
    pub gems: Vec<ResolvedGem>,
    /// Per-gem specs (transitive closure).
    pub specs: Vec<Spec>,
    /// Dependencies block (top-level deps the Gemfile asked for).
    pub dependencies: Vec<String>,
}

/// One resolved gem instance — name + version + source pinning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedGem {
    pub name:    String,
    pub version: String,
    pub source:  crate::source::Source,
    /// Resolved dependencies of this gem (transitive surface).
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// Parse a Gemfile.lock source string into a typed `Lockfile`.
///
/// M0 implementation TBD. Returns a typed `Err` so downstream
/// consumers can wire the public API today and the impl lands
/// when M0 starts.
pub fn parse(_source: &str) -> Result<Lockfile> {
    Err(RubygemsError::LockfileParse(
        "M0 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}

/// Emit a typed `Lockfile` back to bundler-compatible YAML-ish
/// text. Round-trip with `parse` is the M0 acceptance gate.
pub fn emit(_lock: &Lockfile) -> Result<String> {
    Err(RubygemsError::LockfileParse(
        "M0 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
