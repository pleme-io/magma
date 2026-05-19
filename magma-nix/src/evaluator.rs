//! Lazy AST evaluator (M8.2 destination).

use serde::{Deserialize, Serialize};

use crate::{ast::Expr, NixError, Result};

/// Result of evaluating a Nix expression. Lazy values are
/// expanded at projection time; the typed surface here is the
/// fully-evaluated form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
    Null,
    Path(String),
    List(Vec<Value>),
    AttrSet(std::collections::BTreeMap<String, Value>),
    /// A function — un-applied. Materialized into a real value
    /// when applied with an argument.
    Lambda { display_name: String },
    /// A derivation reference — the output of fetcher /
    /// callPackage etc. Carries the BLAKE3 attestation of the
    /// content.
    Derivation { name: String, attestation: String },
}

pub fn evaluate(_expr: &Expr) -> Result<Value> {
    Err(NixError::Eval(
        "M8.2 evaluator not yet implemented — see theory/MAGMA-AS-PLATFORM.md".into(),
    ))
}
