//! magma-nix — in-process Nix expression evaluator + store
//! materialization for Pangea workspaces.
//!
//! Replaces the `nix-build` subprocess + on-disk `/nix/store` for
//! the narrow Nix subset Pangea workspaces use:
//!
//! * `import` (file references + flake imports)
//! * `let ... in ...`
//! * function calls + lambda
//! * attribute sets + selection (`set.attr`)
//! * `fetchurl` / `fetchTarball` (with BLAKE3 + sha256 attestation)
//! * `nixpkgs.callPackage` (gem-derivation entry point bundix uses)
//!
//! Out of scope (refused with a typed error): IFD,
//! `builtins.exec`, arbitrary derivation builders. Pangea
//! workspaces don't use any of these — we refuse rather than
//! silently support them.
//!
//! Per [`theory/MAGMA-AS-PLATFORM.md`](https://github.com/pleme-io/theory/blob/main/MAGMA-AS-PLATFORM.md) §IV.M8.
//! Pairs with `magma-rubygems` M7 (bundix-equivalent gemset.nix
//! emission); magma-nix evaluates the gemset.nix magma-rubygems
//! emits.
//!
//! # Crate status
//!
//! M8 not yet started. This file is the typed API skeleton +
//! module decomposition; each milestone fills in modules per the
//! roadmap.
//!
//! # Module map
//!
//! | Submodule | Purpose | Milestone |
//! |---|---|---|
//! | [`ast`] | Typed Nix expression AST | M8.0 |
//! | [`parser`] | Nix → AST lexer + parser | M8.1 |
//! | [`evaluator`] | Lazy AST evaluator | M8.2 |
//! | [`store`] | In-memory content-addressed store | M8.3 |
//! | [`fetcher`] | fetchurl / fetchTarball with attestation | M8.4 |
//! | [`bundix`] | gemset.nix emission from magma-rubygems Lockfile | M7 |

#![deny(unsafe_code)]
#![allow(dead_code)] // M8 stub.

pub mod ast;
pub mod bundix;
pub mod evaluator;
pub mod fetcher;
pub mod parser;
pub mod store;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NixError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("eval: {0}")]
    Eval(String),
    #[error("fetch: {0}")]
    Fetch(String),
    #[error("store: {0}")]
    Store(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, NixError>;

/// Public API — parse a Nix expression source string into a typed
/// AST.
pub fn parse(source: &str) -> Result<ast::Expr> {
    parser::parse(source)
}

/// Evaluate a parsed AST to a `Value` (laziness handled internally).
pub fn evaluate(expr: &ast::Expr) -> Result<evaluator::Value> {
    evaluator::evaluate(expr)
}
