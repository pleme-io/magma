//! Nix source → typed `ast::Expr` (M8.1 destination).

use crate::{ast::Expr, NixError, Result};

/// Parse a Nix expression source string into a typed AST.
///
/// M8.1 implementation TBD.
pub fn parse(_source: &str) -> Result<Expr> {
    Err(NixError::Parse(
        "M8.1 parser not yet implemented — see theory/MAGMA-AS-PLATFORM.md".into(),
    ))
}
