//! Bridge to `pangea-ruby-eval` (M5 destination).
//!
//! Once a `VirtualGemTree` is materialized, this module produces a
//! `RubyEnvironment` carrying the typed `GEM_PATH` + `RUBYLIB`
//! pointers `pangea-ruby-eval::RubyEvaluator` consumes.
//!
//! The handshake: magma-rubygems owns the tree; pangea-ruby-eval
//! owns the interpreter. Both crates remain independent — the
//! integration point is a serializable env handle.

use serde::{Deserialize, Serialize};

use crate::tree::VirtualGemTree;

/// Typed environment handle the embedded CRuby evaluator consumes.
/// Mirrors what bundler's `bundle exec` injects (GEM_PATH +
/// RUBYLIB) but typed + attested via the gem tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubyEnvironment {
    pub gem_path: std::path::PathBuf,
    /// Optional additional RUBYLIB entries (Pangea workspace lib/).
    pub ruby_lib: Vec<std::path::PathBuf>,
    /// Pinned Ruby version the tree was resolved against. Mismatch
    /// with the interpreter binary is a hard error.
    pub ruby_version: String,
    /// BLAKE3 attestation carried forward from the tree — lets the
    /// evaluator log which closure it's running against.
    pub gem_tree_attestation: String,
}

/// Build a `RubyEnvironment` from a materialized `VirtualGemTree`.
///
/// M5 implementation TBD. Today this returns a placeholder; the
/// real impl will be a few lines once `tree::materialize` lands.
pub fn into_ruby_env(tree: &VirtualGemTree, ruby_version: impl Into<String>) -> RubyEnvironment {
    RubyEnvironment {
        gem_path:              tree.gem_path.clone(),
        ruby_lib:              vec![],
        ruby_version:          ruby_version.into(),
        gem_tree_attestation:  tree.attestation.clone(),
    }
}
