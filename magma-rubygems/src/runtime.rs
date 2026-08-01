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

use crate::load_path::{GemLocator, LoadPathError, resolve_load_path, resolve_load_path_for_roots};
use crate::lockfile::Lockfile;
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
        gem_path: tree.gem_path.clone(),
        ruby_lib: vec![],
        ruby_version: ruby_version.into(),
        gem_tree_attestation: tree.attestation.clone(),
    }
}

/// Build a `RubyEnvironment` directly from a parsed `Lockfile`,
/// resolving the deterministic `RUBYLIB` against gems **already on
/// disk** via `locator` — the path that does not wait for the M4
/// `tree::materialize` fetch+build.
///
/// This is the standardization entry point for the embedded CRuby
/// evaluator: the Gemfile.lock is the single source of truth; the
/// resolved `ruby_lib` is the exact, dependency-ordered closure the
/// interpreter must put on `$LOAD_PATH` — the same set `bundle exec`
/// would inject, computed by a typed interpreter. A lockfile gem no
/// locator can host is a typed [`LoadPathError::MissingGems`], not a
/// downstream `uninitialized constant` Ruby `LoadError`.
///
/// `gem_path` is left empty (the on-disk path consumes `RUBYLIB`
/// directly via prepend, not bundler's `GEM_PATH`); the
/// `gem_tree_attestation` is the resolver's BLAKE3 over the
/// `[(name, version, lib_path)]` closure, so the evaluator logs which
/// closure it ran against.
pub fn resolve_ruby_env(
    lock: &Lockfile,
    locator: &dyn GemLocator,
    ruby_version: impl Into<String>,
) -> Result<RubyEnvironment, LoadPathError> {
    let plan = resolve_load_path(lock, locator)?;
    Ok(RubyEnvironment {
        gem_path: std::path::PathBuf::new(),
        ruby_lib: plan.load_path,
        ruby_version: ruby_version.into(),
        gem_tree_attestation: plan.attestation,
    })
}

/// Like [`resolve_ruby_env`] but resolves only the transitive closure
/// of `roots` (the declared required gems) — see
/// [`resolve_load_path_for_roots`]. This is the entry point the
/// operator uses, so a workspace's dev/test-group gems (rspec,
/// simplecov, …) that the image doesn't bundle never trigger a
/// spurious missing-gem failure.
pub fn resolve_ruby_env_for_roots(
    lock: &Lockfile,
    locator: &dyn GemLocator,
    roots: &[String],
    ruby_version: impl Into<String>,
) -> Result<RubyEnvironment, LoadPathError> {
    let plan = resolve_load_path_for_roots(lock, locator, roots)?;
    Ok(RubyEnvironment {
        gem_path: std::path::PathBuf::new(),
        ruby_lib: plan.load_path,
        ruby_version: ruby_version.into(),
        gem_tree_attestation: plan.attestation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::ResolvedGem;
    use crate::source::Source;
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct MapLocator(HashMap<String, PathBuf>);
    impl GemLocator for MapLocator {
        fn locate(&self, g: &ResolvedGem) -> Option<PathBuf> {
            self.0.get(&g.name).cloned()
        }
    }

    fn gem(name: &str, deps: &[&str]) -> ResolvedGem {
        ResolvedGem {
            name: name.into(),
            version: "0.1.0".into(),
            source: Source::default_rubygems(),
            depends_on: deps.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn resolve_ruby_env_fills_rubylib_in_dependency_order() {
        let lock = Lockfile {
            gems: vec![gem("dependent", &["base"]), gem("base", &[])],
            ..Lockfile::default()
        };
        let loc = MapLocator(
            [
                ("base".to_string(), PathBuf::from("/g/base/lib")),
                ("dependent".to_string(), PathBuf::from("/g/dependent/lib")),
            ]
            .into_iter()
            .collect(),
        );
        let env = resolve_ruby_env(&lock, &loc, "3.3.0").expect("resolves");
        assert_eq!(
            env.ruby_lib,
            vec![
                PathBuf::from("/g/base/lib"),
                PathBuf::from("/g/dependent/lib")
            ]
        );
        assert_eq!(env.ruby_version, "3.3.0");
        assert_eq!(env.gem_tree_attestation.len(), 64);
    }

    #[test]
    fn resolve_ruby_env_propagates_missing_gem_error() {
        let lock = Lockfile {
            gems: vec![gem("present", &[]), gem("absent", &[])],
            ..Lockfile::default()
        };
        let loc = MapLocator(
            [("present".to_string(), PathBuf::from("/g/present/lib"))]
                .into_iter()
                .collect(),
        );
        let err = resolve_ruby_env(&lock, &loc, "3.3.0").unwrap_err();
        let LoadPathError::MissingGems(m) = err;
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "absent");
    }
}
