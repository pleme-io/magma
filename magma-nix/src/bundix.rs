//! bundix-equivalent: emit `gemset.nix` from a magma-rubygems
//! Lockfile (M7 destination).
//!
//! Produces a typed `ast::Expr` matching what bundix emits today,
//! ready for round-tripping through magma-nix's evaluator. The
//! emitted gemset.nix is byte-identical to bundix's output for
//! every Pangea Gemfile.lock — acceptance gate for M7.

use crate::{NixError, Result, ast::Expr};

/// Emit gemset.nix as a typed Nix AST from a magma-rubygems
/// `Lockfile`. The Lockfile is passed as serde_json::Value to
/// avoid a magma-rubygems dep (forward-only — magma-nix doesn't
/// depend on magma-rubygems; magma-rubygems orchestrates the
/// emission via this entry point).
pub fn emit_gemset(_lockfile_json: &serde_json::Value) -> Result<Expr> {
    Err(NixError::Eval(
        "M7 bundix-equivalent not yet implemented — see theory/MAGMA-AS-PLATFORM.md".into(),
    ))
}
